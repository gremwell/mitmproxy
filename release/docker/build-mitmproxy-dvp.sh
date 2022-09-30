#!/bin/sh -xe

VERSION=8.1.1

[ -f mitmproxy-$VERSION-py3-none-any.whl ] || \
	wget https://snapshots.mitmproxy.org/$VERSION/mitmproxy-$VERSION-py3-none-any.whl
docker build -t mitmproxy-dvp --build-arg MITMPROXY_WHEEL=mitmproxy-$VERSION-py3-none-any.whl .
