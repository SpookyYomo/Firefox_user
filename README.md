# Firefox user.js
This is a Firefox user.js that tries to modify from this [gist (or
newer)](https://gist.github.com/brainfucksec/68e79da1c965aeaa4782914afd8f7fa2).
This has recently been expanded to also modify with reference to
[Betterfox](https://github.com/yokoffing/Betterfox), in particular, user.js as
in the repo, which is a combination of every other "distribution" in Betterfox.

## Keeping track with upstream
`git remote add upstream git@gist.github.com:68e79da1c965aeaa4782914afd8f7fa2.git`,
then perform the diff's as necessary, with
`git difftool (-d) upstream/master:user.js user.js`.

## System-wide user.js
Currently detailed
[here](https://github.com/SpookyYomo/dotfiles/tree/main/Firefox/usr/lib/firefox#system-wide-userjs).
There is a corresponding Makefile command that translates the user.js into
appropriate firefox.cfg.
