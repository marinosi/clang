// RUN: %clang_cc1 -fsyntax-only -verify %s
template<class T> struct A {
  static T t; // expected-error{{static data member instantiated with function type 'int ()'}}
};
typedef int function();
A<function> a; // expected-note{{instantiation of}}

template<typename T> struct B {
  B() { T t; } // expected-error{{variable instantiated with function type 'int ()'}}
};
B<function> b; // expected-note{{instantiation of}}
