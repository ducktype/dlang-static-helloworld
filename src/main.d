import std;
import core.sys.linux.sched;
import core.thread;

extern (C) __gshared string[] rt_options = ["gcopt=disable:0 parallel:2"];

void main()
{
    auto p = new char[10];
    p[3] = 'a';
    int[string] aa;   // Associative array of ints that are
                  // indexed by string keys.
                  // The KeyType is string.
aa["hello"] = 3;  // set value associated with key "hello" to 3
int value = aa["hello"];  // lookup value from a key
assert(value == 3);

    auto err = unshare(CLONE_NEWNS|CLONE_NEWUSER);

    writeln(err);

    Thread.sleep(dur!("seconds")( 200 ));

  writeln("end");    
}