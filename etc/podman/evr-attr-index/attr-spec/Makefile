tests_inputs := $(wildcard tests/*.in.xml)
tests := $(basename $(basename $(tests_inputs)))
tests_passed := $(addsuffix .pass, $(tests))

.PHONY: all
all:

.PHONY: check
check: $(tests_passed) $(addsuffix .out.xml, $(test))

.PHONY: install
install:

.PHONY: clean
clean:
	rm -f tests/*.diff tests/*.out.xml

tests/%.pass: tests/%.diff
	test ! -s $^
	touch $@

tests/%.diff: tests/%.out.xml tests/%.expected.xml
	diff $^ > $@

tests/%.out.xml: tests/%.in.xml attr-trans.xslt
	xsltproc attr-trans.xslt $(firstword $^) | xmllint --format - > $@
	cp $@ `echo $@ | sed s/out/proposed/`
