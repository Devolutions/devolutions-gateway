#!/bin/sh

PRE_COMMIT_HOOK=./.git/hooks/pre-commit

if test -f "$PRE_COMMIT_HOOK"; then
	echo "$(tput setaf 1)$PRE_COMMIT_HOOK already exists"
	exit 1
fi

echo "#!/bin/sh
cargo +stable fmt --all -- --check 2> /dev/null
if ! [ \$? -eq 0 ] ; then
    printf \"\n\$(tput setaf 3)Bad formatting, please run 'cargo +stable fmt' and stage modifications\n\n\"
    exit 1
fi" > "$PRE_COMMIT_HOOK"
chmod +x "$PRE_COMMIT_HOOK"
echo "$(tput setaf 2)$PRE_COMMIT_HOOK created"

