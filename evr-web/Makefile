apps := attr-index-explorer join upload

app_dist_dirs := $(addprefix dist/, $(apps))
app_dist_index_htmls := $(addsuffix /index.html, $(app_dist_dirs))
app_dist_app_js := $(addsuffix /app.js, $(app_dist_dirs))
app_dist_app_css := $(addsuffix /app.css, $(app_dist_dirs))

# defines the release mode. possible options are either 'development'
# or 'production'.
release_mode := development

.PHONY: all
all: $(app_dist_index_htmls) $(app_dist_app_js) $(app_dist_app_css) dist/base.css dist/index.html dist/index.css

.PHONY: clean
clean:
	rm -rf dist

dist/%/index.html: src/%/index.html
	mkdir -p `dirname $@`
	cp $^ $@

dist/%/app.js: src/%/webpack.config.js src/webpack.config.common.js src/%/*.js src/*.js
	mkdir -p `dirname $@`
	./node_modules/.bin/webpack --config $(firstword $^) --mode=$(release_mode)

dist/%/app.css: src/%/index.css
	mkdir -p `dirname $@`
	cp $^ $@

dist/base.css: src/base.css
	mkdir -p `dirname $@`
	cp $^ $@

dist/index.html: src/index.html
	mkdir -p `dirname $@`
	cp $^ $@

dist/index.css: src/index.css
	mkdir -p `dirname $@`
	cp $^ $@
