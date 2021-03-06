// RUN: %clang_cc1 %s -fcxx-exceptions -fexceptions -fsyntax-only -Wignored-qualifiers -verify

int test1() {
  throw;
}

// PR5071
template<typename T> T f() { }

template<typename T>
void g(T t) {
  return t * 2; // okay
}

template<typename T>
T h() {
  return 17;
}

// Don't warn on cv-qualified class return types, only scalar return types.
namespace ignored_quals {
struct S {};
const S class_c();
const volatile S class_cv();

const int scalar_c(); // expected-warning{{'const' type qualifier on return type has no effect}}
int const scalar_c2(); // expected-warning{{'const' type qualifier on return type has no effect}}

const
char*
const // expected-warning{{'const' type qualifier on return type has no effect}}
f();

char
const*
const // expected-warning{{'const' type qualifier on return type has no effect}}
g();

char* const h(); // expected-warning{{'const' type qualifier on return type has no effect}}
char* volatile i(); // expected-warning{{'volatile' type qualifier on return type has no effect}}

const volatile int scalar_cv(); // expected-warning{{'const volatile' type qualifiers on return type have no effect}}
}

namespace PR9328 {
  typedef char *PCHAR;
  class Test 
  {
    const PCHAR GetName() { return 0; } // expected-warning{{'const' type qualifier on return type has no effect}}
  };
}
