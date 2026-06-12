# Compilation du rapport LaTeX

Depuis ce dossier :

```bash
# 1. Exporter le schéma (une fois votre SVG finalisé)
inkscape architecture/schema.svg --export-filename=architecture/schema.pdf

# 2. Compiler le rapport
pdflatex rapport.tex
pdflatex rapport.tex   # second pass pour les références
```

Prérequis : TeX Live (`pdflatex`), Inkscape (export SVG→PDF).

Sortie : `docs/rapport.pdf`
