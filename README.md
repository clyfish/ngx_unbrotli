The `ngx_unbrotli` module is a filter that decompresses responses with `Content-Encoding: br` for clients that do not support `brotli` encoding method.

#### Build

```bash
./build_brotli.sh
cd path/to/nginx-src
./configure --with-compat --add-dynamic-module=path/to/ngx_unbrotli
make modules
cp objs/ngx_http_unbrotli_filter_module.so path/to/nginx/modules
```

#### Usage

`load_module modules/ngx_http_unbrotli_filter_module.so;`

Usage is similar to [ngx_http_gunzip_module](http://nginx.org/en/docs/http/ngx_http_gunzip_module.html)

- Replace `gunzip` with `unbrotli`
- Replace `gunzip_buffers` with `unbrotli_buffers`
