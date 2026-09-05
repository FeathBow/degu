# degu's little HPC adventure

A small, interactive introduction to Slurm and careful HPC storage cleanup. Deliver a job, understand its queue state, read the result, and help a curious degu make room for the next experiment.

The adventure supports English and Simplified Chinese, light and dark themes, keyboard interaction, and reduced motion.

**This is a browser simulation.** Its jobs, paths, quotas, and downloaded receipts are fictional. It does not connect to a cluster or change real files.

- Project: <https://github.com/FeathBow/degu>
- Intended website address: <https://feathbow.github.io/degu/>

## Run locally

From this branch's directory:

```sh
python3 -m http.server 4173 --bind 127.0.0.1
```

Open <http://127.0.0.1:4173/>. The site uses native HTML, CSS, and JavaScript; there is no dependency installation, build step, backend, or analytics service. Language and theme preferences are stored in the visitor's browser.

## Branch contents

`gh-pages` has independent history and contains the standalone website. Keep website updates on this branch; `main` can link to the experience.

- `index.html`: entry page and link-preview metadata.
- `assets/`: original artwork, favicon, and social preview image.
- `src/`: tutorial logic, translations, and browser interactions.
- `styles/`: layouts, themes, and motion.
- `.nojekyll`: serve the static files without Jekyll processing.
- `.gitignore`: limit additions to the site and exclude local configuration.
- `LICENSE-APACHE` and `LICENSE-MIT`: the project's existing licenses.

The JavaScript files are editable source files. Review the exact file list before committing; ignore rules are not a sensitive-information scanner.

## Publish after approval

After the owner approves public publication, select **Deploy from a branch** in the repository's Pages settings, then select `gh-pages` and `/(root)`. Once configured, pushing to this branch updates the public website.

The branch is public when pushed to this public repository. Website visitors can also inspect the HTML, CSS, JavaScript, and artwork their browser downloads.

## License

Dual-licensed under Apache-2.0 or MIT, following the degu project.
