"""Assert declared guidance reaches the real pinned harness provider request.

The loopback provider scripts only the external response; this does not claim
model comprehension or access any real account credentials.
"""
import argparse
import http.server
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import tomllib

parser = argparse.ArgumentParser()
parser.add_argument('--omp', required=True)
parser.add_argument('--seat', required=True)
parser.add_argument('--output', required=True)
args = parser.parse_args()
with open(args.seat, 'rb') as source:
    guidance = tomllib.load(source)['conversation']['guidance']
assert guidance.strip()
requests = []

class Provider(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        body = json.dumps({'data': [{'id': 'prompt-capture', 'object': 'model'}]}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        requests.append({'path': self.path, 'payload': payload})
        chunks = [
            {'id': 'chatcmpl-probe', 'object': 'chat.completion.chunk', 'created': 1,
             'model': 'prompt-capture', 'choices': [{'index': 0, 'delta': {'role': 'assistant', 'content': 'Acknowledged.'}, 'finish_reason': None}]},
            {'id': 'chatcmpl-probe', 'object': 'chat.completion.chunk', 'created': 1,
             'model': 'prompt-capture', 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]},
        ]
        body = ''.join('data: ' + json.dumps(chunk) + '\n\n' for chunk in chunks) + 'data: [DONE]\n\n'
        encoded = body.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Content-Length', str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

with tempfile.TemporaryDirectory(prefix='odin-model-prompt-') as temporary:
    root = Path(temporary)
    home, agent, workspace = (root / name for name in ('home', 'agent', 'workspace'))
    for directory in (home, agent, workspace):
        directory.mkdir()
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Provider)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    (agent / 'models.yml').write_text(json.dumps({'providers': {'odin-prompt-probe': {
        'baseUrl': f'http://127.0.0.1:{port}/v1', 'api': 'openai-completions',
        'apiKey': 'isolated-probe-key', 'models': [{'id': 'prompt-capture', 'name': 'Prompt Capture',
        'reasoning': False, 'input': ['text'], 'contextWindow': 131072, 'maxTokens': 256,
        'cost': {'input': 0, 'output': 0, 'cacheRead': 0, 'cacheWrite': 0}}],
    }}}))
    environment = {'HOME': str(home), 'PI_CODING_AGENT_DIR': str(agent),
                   'PATH': os.environ['PATH'], 'TERM': 'dumb', 'NO_COLOR': '1'}
    command = [args.omp, '--provider', 'odin-prompt-probe', '--model', 'prompt-capture',
               '--mode', 'json', '--print', '--no-session', '--no-title', '--no-prewalk',
               '--no-tools', '--no-lsp', '--no-pty', '--no-extensions', '--no-skills', '--no-rules',
               '--append-system-prompt', guidance, 'Acknowledge this isolated prompt capture.']
    print(f'PROVIDER_READY port={port}', flush=True)
    try:
        result = subprocess.run(command, cwd=workspace, env=environment,
                                input='', capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired as error:
        def decoded(value):
            return value.decode('utf-8', 'replace') if isinstance(value, bytes) else (value or '')
        result = subprocess.CompletedProcess(
            command, 124, decoded(error.stdout), decoded(error.stderr))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    messages = [message for request in requests for message in request['payload'].get('messages', [])]
    def text_content(message):
        content = message.get('content', '')
        return content if isinstance(content, str) else '\n'.join(
            part.get('text', '') for part in content if isinstance(part, dict))
    bound = [message for message in messages if message.get('role') in ('system', 'developer')
             and guidance in text_content(message)]
    evidence = {
        'executable': args.omp,
        'seat_declaration': args.seat,
        'returncode': result.returncode,
        'request_count': len(requests),
        'request_paths': [request['path'] for request in requests],
        'model_ids': [request['payload'].get('model') for request in requests],
        'guidance_sha256': hashlib.sha256(guidance.encode()).hexdigest(),
        'guidance_in_model_prompt': bool(bound),
        'tool_counts': [len(request['payload'].get('tools') or []) for request in requests],
    }
    Path(args.output).write_text(json.dumps(evidence, indent=2))
    assert result.returncode == 0, result.stderr
    assert bound, 'declared guidance did not reach a model system/developer message'
    assert all(not request['payload'].get('tools') for request in requests), 'unexpected tool authority'
    print(json.dumps({'requests': len(requests), 'guidance_in_model_prompt': True,
                      'tools': 'none', 'proof': args.output}), flush=True)
