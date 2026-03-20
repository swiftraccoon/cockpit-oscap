# cockpit-oscap

OpenSCAP compliance scanning for [Cockpit](https://cockpit-project.org/).

Based on [cockpit-project/starter-kit](https://github.com/cockpit-project/starter-kit).

## Development dependencies

On Fedora:

    sudo dnf install gettext nodejs npm make

## Getting and building the source

```
git clone https://github.com/swiftraccoon/cockpit-oscap.git
cd cockpit-oscap
make
```

## Installing

`make install` compiles and installs the package in `/usr/local/share/cockpit/`. The
convenience targets `srpm` and `rpm` build the source and binary rpms,
respectively.

For development, run `make devel-install` to link the checkout into Cockpit's
package lookup path. Or manually:

```
mkdir -p ~/.local/share/cockpit
ln -s `pwd`/dist ~/.local/share/cockpit/oscap
```

After changing the code and running `make` again, reload the Cockpit page in
your browser.

Watch mode rebuilds automatically on code changes:

    make watch

To uninstall the locally installed version:

    make devel-uninstall

## Running eslint

    npm run eslint
    npm run eslint:fix

## Running stylelint

    npm run stylelint
    npm run stylelint:fix

## Further reading

 * [Cockpit Deployment and Developer documentation](https://cockpit-project.org/guide/latest/)
 * [Make your project easily discoverable](https://cockpit-project.org/blog/making-a-cockpit-application.html)
