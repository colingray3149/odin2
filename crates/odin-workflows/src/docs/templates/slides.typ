// Slides for docs.render's slides template: Touying's simple theme in the Odin accent.
// Level-1 headings open sections; level-2 headings start slides.
#import "@preview/touying:0.8.0": *
#import themes.simple: *
#import "odin.typ": ink, sans-fonts, raw-fonts

#let slides(title: none, phone: false, body) = {
  show: simple-theme.with(aspect-ratio: "16-9", config-colors(primary: ink))
  set text(font: sans-fonts)
  show raw: set text(font: raw-fonts)
  if title != none { title-slide(text(size: 1.6em, weight: "bold", fill: ink, title)) }
  body
}
