test:
	lua5.4 tests/test.lua

sample:
	lua5.4 examples/make_log.lua
	lua5.4 bin/access-log-hunter examples/access.log > docs/sample-output.txt; true
	lua5.4 bin/access-log-hunter examples/access.log --html > site/index.html
