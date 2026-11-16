// The template library docs.render writes beside main.typ. theme.typ comes from the
// declared docs-theme root (dotfiles colors.nix); meta.json holds the call's meta facts.
#import "theme.typ": accent, secondary
#import "@preview/codly:1.3.0": codly, codly-init

// Print-safe shades of the screen palette.
#let ink = accent.darken(45%)
#let link-ink = secondary.darken(35%)

// Keep the Latin typography first; these families ship in the offline wrapper.
// Other scripts can use Typst's automatic fallback from the bundled Noto collection.
#let sans-fonts = ("Inter", "Libertinus Sans", "Noto Sans", "Noto Sans CJK JP", "Noto Sans CJK SC", "Noto Sans CJK KR", "Noto Sans Devanagari", "Noto Color Emoji")
#let serif-fonts = ("Libertinus Serif", "New Computer Modern", "Noto Serif", "Noto Serif CJK JP", "Noto Serif CJK SC", "Noto Serif CJK KR", "Noto Serif Devanagari", "Noto Color Emoji")
#let raw-fonts = ("JetBrains Mono",) + sans-fonts.slice(2)

#let base(title: none, phone: false, body) = {
  set document(title: title)
  set page(
    // A5 still reads at phone width, and leaves a table room for three readable columns.
    paper: if phone { "a5" } else { "us-letter" },
    margin: if phone { 12mm } else { 22mm },
    numbering: "1",
    number-align: center,
  )
  set text(font: serif-fonts, size: if phone { 11pt } else { 10.5pt }, lang: "en")
  set par(justify: not phone, leading: 0.7em)
  show heading: set text(fill: ink, font: sans-fonts, weight: "semibold")
  show heading: set block(above: 1.4em, below: 0.8em)
  // Only web and mail links open from a PDF reader; a link to a saved file is its text.
  show link: it => {
    let opens = type(it.dest) != str or it.dest.starts-with("https://") or it.dest.starts-with("http://") or it.dest.starts-with("mailto:")
    if opens { text(fill: link-ink, it) } else { it.body }
  }
  show raw: set text(font: raw-fonts, size: 0.92em)
  show: codly-init.with()
  codly(zebra-fill: none, stroke: 0.5pt + ink.lighten(60%))
  set table(inset: 5pt, stroke: (x, y) => if y == 0 { (bottom: 0.6pt + ink) } else { (bottom: 0.3pt + ink.lighten(75%)) })
  show table.cell.where(y: 0): set text(weight: "semibold")
  // A picture keeps to 8 cm high, so a headshot shares its page with the text about it.
  show image: it => context {
    let height = measure(it).height
    if height > 8cm { scale(8cm / height * 100%, reflow: true, it) } else { it }
  }
  // A cell wraps inside its column: smaller ragged text, and an address or URL too long for
  // the column breaks anywhere instead of running into the next one.
  show table.cell: it => {
    // Pandoc centres the figure around a table; its cells still read from the start.
    set align(start)
    set text(size: 0.9em, hyphenate: true)
    set par(justify: false, leading: 0.55em)
    show regex("\S{18,}"): word => word.text.clusters().join(sym.zws)
    it
  }
  if title != none {
    block(below: 1.2em, text(size: 1.9em, weight: "bold", fill: ink, font: sans-fonts, title))
  }
  body
}

#let report(title: none, phone: false, body) = base(title: title, phone: phone, body)

#let plain(title: none, phone: false, body) = base(title: title, phone: phone, {
  show heading: set text(fill: black)
  body
})

#let letter(title: none, phone: false, body) = base(title: none, phone: phone, {
  set par(justify: false)
  body
})

// The measured run facts close the research report; missing values remain unavailable.
#let research(title: none, phone: true, body) = {
  let meta = json("meta.json")
  let fact(key) = meta.at(key, default: "unavailable")
  base(title: title, phone: phone, {
    body
    v(1.5em)
    block(stroke: (top: 0.6pt + ink), inset: (top: 0.6em), width: 100%, text(size: 0.85em)[
      Run: #fact("model") · #fact("wall_time") · #fact("tool_calls") tool calls ·
      #fact("sites") sites read · list-price estimate #fact("cost")
    ])
  })
}
