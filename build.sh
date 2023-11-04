#!/usr/bin/env bash

#EXTERNAL COMMANDS USED BY THIS BUILD SCRIPT: wget mkdir tar strip

#SOME BASH SNIPPETS:
#path=/foo/bar/bim/baz/file.gif
#file=${path##*/}
##$file is now 'file.gif'
##Remove the extension from a path-string:
#base=${file%.*}
##remove specific multiple extensions from file
#base2=${file%.tar.xz}
##${base} is now 'file'.
##keep dirname of a path
#dir=${path%/*}
##dir is now /foo/bar/bim/baz

#DOC LINKS:
#https://aykevl.nl/2018/04/codesize

#PURE BASH FUNCTION TO DETERMINE THE CURRENT BASH SCRIPT DIRECTORY ABSOLUTE PATH:
get_script_dir() {
  local wdir
  local scriptdir
  wdir="$PWD"; [ "$PWD" = "/" ] && wdir=""
  case "$0" in
    /*) scriptdir="${0}";;
    *) scriptdir="$wdir/${0#./}";;
  esac
  scriptdir="${scriptdir%/*}"
  REPLY=$scriptdir
}

get_script_dir
script_dir=$REPLY
dname=${script_dir##*/}
#echo $script_dir

#url="https://ziglang.org/builds/zig-linux-x86_64-0.11.0-dev.2639+4df87b40f.tar.xz"
url="https://ziglang.org/builds/zig-linux-x86_64-0.12.0-dev.926+3be8490d8.tar.xz"
url_file=${url##*/}
#url_dir=${url_file%.tar.xz}
#echo $url
#echo $url_file
#echo $url_dir
#exit


if [[ ! -e $script_dir/build/zig ]]
then
  mkdir -p $script_dir/build
  if [[ ! -e $script_dir/build/$url_file ]]
  then
    echo "downloading zig compiler..."
    wget -q $url -O $script_dir/build/$url_file
    if [ $? -ne 0 ]; then { echo "compiler download failed, aborting." ; exit 1; } fi
  fi
  echo "extracting zig compiler..."
  mkdir -p $script_dir/build/zig
  tar --strip-components=1 -xf $script_dir/build/$url_file -C $script_dir/build/zig
  #mv $script_dir/$url_dir $script_dir/zig
  if [ $? -ne 0 ]; then { echo "compiler extraction failed, aborting." ; exit 1; } fi
fi

echo "building $dname..."
#./zig/zig cc -static -target x86_64-linux-musl treerun.c --name treerun
#$script_dir/zig/zig cc -static -target x86_64-linux-musl $script_dir/bix.c -o $script_dir/bix -s
#$script_dir/zig/zig c++ -static -target x86_64-linux-musl -x c++ -fno-rtti -fno-exceptions -nodefaultlibs -nostdinc -nostdinc++ -nostdlib++ -Wno-write-strings -s -ffunction-sections -fdata-sections -flto -Wl,--gc-sections $script_dir/bix.c -o $script_dir/bix
$script_dir/build/zig/zig c++ -std=c++2b -static -target x86_64-linux-musl -fno-rtti -fno-exceptions -Wno-write-strings -fno-ident -s -ffunction-sections -fdata-sections -flto -Wl,--gc-sections -Wl,--no-eh-frame-hdr -fno-unwind-tables $script_dir/src/main.cc -o $script_dir/bin/$dname
if [ $? -ne 0 ]; then { echo "compilation failed, aborting." ; exit 1; } fi

strip -R .comment $script_dir/bin/$dname #because clang flag -fno-ident does not seems to work

#ldd $script_dir/treerun
echo "done"