# DFIR Lab Writeups

Source for [elian0x.github.io](https://elian0x.github.io) — a Jekyll site (Chirpy theme) collecting Incident Response / Digital Forensics lab writeups. Built and deployed automatically by GitHub Actions on every push to `main`.

## Adding a new writeup

1. Copy `WRITEUP_TEMPLATE.md` into `_posts/` and rename it — the filename must start with the post date:
   ```
   _posts/2026-07-27-my-new-writeup.md
   ```
2. Fill in the front matter (`title`, `date`, `categories`, `tags`, `description`).
3. Fill in the report sections. Drop any screenshots into `assets/img/`.
4. Commit and push:
   ```
   git add .
   git commit -m "Add writeup: <title>"
   git push
   ```
5. Check the **Actions** tab on GitHub for build status — the site updates within ~1-2 minutes of a successful build.

## Local preview (optional)

Requires Ruby + Bundler.

```powershell
bundle install
bundle exec jekyll serve
```

Then open http://localhost:4000
