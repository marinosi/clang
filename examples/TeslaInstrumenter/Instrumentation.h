/*-
 * Copyright (c) 2011 Jonathan Anderson, Steven J. Murdoch
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/// \file Instrumentation and some subclasses.

#ifndef TESLA_INSTRUMENTATION_H
#define TESLA_INSTRUMENTATION_H

#include <map>
#include <set>

#include "clang/AST/AST.h"


/// Some instrumentation code.
///
/// For instance, before assigning to a variable, an Instrumentation instance
/// might call out to a function which says "yes, this is ok."
class Instrumentation {
  public:
    /// Creates the actual instrumentation code.
    virtual std::vector<clang::Stmt*> create(clang::ASTContext &ast) = 0;

    /// Inserts the instrumentation before a particular Stmt.
    std::vector<clang::Stmt*> insert(
        const clang::Stmt *before, clang::CompoundStmt *c,
        clang::ASTContext &ast);

    /// Inserts the instrumentation at the beginning of a CompoundStmt.
    std::vector<clang::Stmt*> insert(
        clang::CompoundStmt *c, clang::ASTContext &ast) {
      if (c->children()) return insert(*c->children(), c, ast);
      else return append(c, ast);
    }

    /// Inserts the instrumentation before a particular Stmt.
    std::vector<clang::Stmt*> insert_after(
        const clang::Stmt *before, clang::CompoundStmt *c,
        clang::ASTContext &ast);

    /// Replaces a number of statements with instrumentation.
    std::vector<clang::Stmt*> replace(clang::CompoundStmt *c, clang::Stmt *s,
        clang::ASTContext &ast, size_t len = 1);

    /// Appends the instrumentation to the end of a CompoundStmt.
    std::vector<clang::Stmt*> append(
        clang::CompoundStmt *c, clang::ASTContext &ast);

    /// The name of the event handler function.
    std::string eventHandlerName(const std::string &suffix) const;

  protected:
  /// Turn an expression into an L-Value.
  ///
  /// When we call instrumentation, we don't want to evaluate expressions
  /// twice (e.g. 'return foo();' -> '__instrument(foo()); return foo();').
  /// Instead, we should create a temporary variable and assign it just before
  /// we would normally take the instrumentated action:
  ///
  /// T *tmp;
  /// ...
  /// tmp = foo();
  /// __instrument(tmp);
  /// return tmp;
  ///
  /// @returns a pair containing 1) an expression which references the temporary
  ///          variable, and 2) the statement which initializes it
  std::pair<clang::Expr*, std::vector<clang::Stmt*> > makeLValue(
      clang::Expr *e, const std::string& name,
      clang::DeclContext *dc, clang::ASTContext &ast,
      clang::SourceLocation location = clang::SourceLocation());

  std::string typeIdentifier(const clang::QualType t) const;
  std::string typeIdentifier(const clang::Type *t) const;

  private:
    const static std::string PREFIX;
};


/// Instruments an assertion's point of declaration.
class TeslaAssertion : public Instrumentation {
  public:
    enum StorageClass {
      UNKNOWN,
      GLOBAL,
      PER_THREAD
    };

    /// Maps functions to lists of parameters.
    typedef std::map<clang::FunctionDecl*, std::vector<clang::Expr*> >
      FunctionParamMap;

    /// Constructor.
    ///
    /// @param  e           the expression which might be the 'TESLA' marker
    /// @param  cs          the CompoundStmt that e is found in
    /// @param  f           the function the alleged assertion is made in
    /// @param  assertCount how many assertions have already been made in f
    /// @param  d           where to output errors and warnings
    TeslaAssertion(clang::Expr *e, clang::CompoundStmt *cs,
        clang::FunctionDecl *f, int assertCount, clang::Diagnostic& d);

    TeslaAssertion(const TeslaAssertion& original);
    TeslaAssertion& operator= (const TeslaAssertion& rhs);

    bool isValid() const {
      return ((parent != NULL) and (marker != NULL) and (assertion != NULL)
          and (scopeBegin != NULL) and (scopeEnd != NULL));
    }

    std::string getName() const { return handlerName; }
    StorageClass getStorageClass() const { return storage; }
    const clang::FunctionDecl *getDeclaringFunction() const { return f; }
    const clang::FunctionDecl *getScopeBegin() const { return scopeBegin; }
    const clang::FunctionDecl *getScopeEnd() const { return scopeEnd; }

    const FunctionParamMap& getReferencedFunctions() const { return functions; }

    size_t getVariableCount() const { return variableRefs.size(); }
    const clang::ValueDecl* getVariable(size_t i) const;

    /// Returns the actual CallExpr which marks the assertion start.
    const clang::CallExpr* getMarker() const { return marker; }

    /// Returns the assertion block.
    const clang::CompoundStmt* getBlock() const { return assertion; }

    // Instrumentation implementation
    virtual std::vector<clang::Stmt*> create(clang::ASTContext &ast);

  private:
    /// Recursively searches for variable and function references.
    void searchForReferences(clang::Stmt* s);

    clang::Diagnostic& diag;          ///< where we can report problems

    clang::FunctionDecl *f;           ///< function containing the assertion
    std::string handlerName;          ///< name of event handler
    int assertCount;                  ///< existing assertions in function
    clang::CompoundStmt *parent;      ///< where the assertion lives

    clang::CallExpr *marker;          ///< marks the beginning of an assertion
    clang::CompoundStmt *assertion;   ///< block of assertion "expressions"

    StorageClass storage;             ///< where automata state is stored
    clang::FunctionDecl *scopeBegin;  ///< where the automata start running
    clang::FunctionDecl *scopeEnd;    ///< where the automata finish running

    /// variables referenced in the assertion
    std::vector<clang::Expr*> variableRefs;
    std::set<clang::Decl*> variables;   ///< for uniqification (unordered!)

    /// functions referenced in the assertion, and the variables they refer to
    FunctionParamMap functions;
};


/// Instruments entry into a function.
class FunctionEntry : public Instrumentation {
  public:
    /// Constructor.
    ///
    /// @param  function      the function whose scope we are instrumenting
    /// @param  teslaDataType the 'struct __tesla_data' type
    FunctionEntry(clang::FunctionDecl *function, clang::QualType teslaDataType);

    virtual std::vector<clang::Stmt*> create(clang::ASTContext &ast);

  private:
    std::string name;

    clang::FunctionDecl *f;               ///< where we can declare things
    clang::QualType teslaDataType;        ///< the type we store scoped data in
    clang::SourceLocation location;       ///< where we pretend to exist
};


/// Instruments a return from a function.
class FunctionReturn : public Instrumentation {
  public:
    /// Constructor.
    ///
    /// @param  function      the function whose scope we are instrumenting
    /// @param  r             the return statement
    FunctionReturn(clang::FunctionDecl *function, clang::ReturnStmt *r);

    virtual std::vector<clang::Stmt*> create(clang::ASTContext &ast);

  private:
    std::string name;

    clang::FunctionDecl *f;               ///< where we can declare things
    clang::ReturnStmt *r;                 ///< to instrument (NULL if void)
    clang::SourceLocation location;       ///< where we pretend to exist
};

/// A value is being assigned to a structure of interest.
class FunctionCall : public Instrumentation {
  public:
    FunctionCall(clang::FunctionDecl *function,
            std::vector<clang::Expr *> Params,
            std::string instr_func, clang::DeclContext *dc);

    virtual std::vector<clang::Stmt*> create(clang::ASTContext &ast);

  private:
    std::string name;

    clang::FunctionDecl *F;
    std::vector<clang::Expr *> Params;
    std::string instr_func;
    clang::DeclContext *DC;
};

/// A value is being assigned to a structure of interest.
class FieldAssignment : public Instrumentation {
  public:
    FieldAssignment(clang::MemberExpr *lhs, clang::Expr *rhs,
        clang::DeclContext *dc);

    virtual std::vector<clang::Stmt*> create(clang::ASTContext &ast);

  private:
    clang::MemberExpr *lhs;
    clang::Expr *rhs;
    clang::QualType structType;
    clang::FieldDecl *field;
    clang::DeclContext *dc;
};

#endif // TESLA_INSTRUMENTATION_H
