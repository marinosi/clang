/// \file Instrumentation and some subclasses.

#ifndef TESLA_INSTRUMENTATION_H
#define TESLA_INSTRUMENTATION_H

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
    void insert(clang::CompoundStmt *c, const clang::Stmt *before,
        clang::ASTContext &ast);

    /// Inserts the instrumentation at the beginning of a CompoundStmt.
    void insert(clang::CompoundStmt *c, clang::ASTContext &ast) {
      if (c->children()) insert(c, *c->children(), ast);
      else append(c, ast);
    }

    /// Appends the instrumentation to the end of a CompoundStmt.
    void append(clang::CompoundStmt *c, clang::ASTContext &ast);
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

    clang::DeclContext *declContext;      ///< where we can declare things
    clang::QualType teslaDataType;        ///< the type we store scoped data in
    clang::SourceLocation location;       ///< where we pretend to exist
};


/// Instruments a return from a function.
class FunctionReturn : public Instrumentation {
  public:
    /// Constructor.
    ///
    /// @param  function      the function whose scope we are instrumenting
    FunctionReturn(clang::FunctionDecl *function);

    virtual std::vector<clang::Stmt*> create(clang::ASTContext &ast);

  private:
    std::string name;

    clang::DeclContext *declContext;      ///< where we can declare things
    clang::SourceLocation location;       ///< where we pretend to exist
};

/// A value is being assigned to a structure of interest.
class FieldAssignment : public Instrumentation {
  private:
    const static std::string PREFIX;

    clang::MemberExpr *lhs;
    clang::Expr *rhs;
    clang::QualType structType;
    clang::FieldDecl *field;

    /// The name of the function which we will call to check this assignment.
    std::string checkerName() const;

  public:
    FieldAssignment(clang::MemberExpr *lhs, clang::Expr *rhs);
    virtual std::vector<clang::Stmt*> create(clang::ASTContext &ast);
};

#endif // TESLA_INSTRUMENTATION_H
