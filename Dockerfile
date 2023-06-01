FROM ubuntu:22.04
RUN apt-get update && apt-get install -y build-essential git cmake libpcre3-dev zlib1g-dev libssl-dev wget curl vim
RUN cd /tmp && wget https://nginx.org/download/nginx-1.24.0.tar.gz && tar xf nginx-1.24.0.tar.gz && cd nginx-1.24.0 && ./configure --prefix=/usr/local/nginx --with-http_ssl_module && make install
RUN cd /tmp && git clone https://github.com/clyfish/ngx_unbrotli && cd ngx_unbrotli && ./build_brotli.sh
RUN cd /tmp/nginx-1.24.0 && ./configure --add-dynamic-module=/tmp/ngx_unbrotli --with-http_ssl_module && make modules && mkdir /usr/local/nginx/modules && cp objs/ngx_http_unbrotli_filter_module.so /usr/local/nginx/modules/
