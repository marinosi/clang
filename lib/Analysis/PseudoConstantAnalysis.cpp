//== PseudoConstantAnalysis.cpp - Find Pseudoconstants in the AST-*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file tracks the usage of variables in a Decl body to see if they are
// never written to, implying that they constant. This is useful in static
// analysis to see if a developer might have intended a variable to be const.
//
//===----------------------------------------------------------------------===//

#include "clang/Analysis/Analyses/PseudoConstantAnalysis.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include <deque>

using namespace clang;

// The number of ValueDecls we want to keep track of by default (per-function)
#define VARDECL_SET_SIZE 256
typedef llvm::SmallPtrSet<const VarDecl*, VARDECL_SET_SIZE> VarDeclSet;

PseudoConstantAnalysis::PseudoConstantAnalysis(const Stmt *DeclBody) :
      DeclBody(DeclBody), Analyzed(false) {
  NonConstantsImpl = new VarDeclSet;
  UsedVarsImpl = new VarDeclSet;
}

PseudoConstantAnalysis::~PseudoConstantAnalysis() {
  delete (VarDeclSet*)NonConstantsImpl;
  delete (VarDeclSet*)UsedVarsImpl;
}

// Returns true if the given ValueDecl is never written to in the given DeclBody
bool PseudoConstantAnalysis::isPseudoConstant(const VarDecl *VD) {
  // Only local and static variables can be pseudoconstants
  if (!VD->hasLocalStorage() && !VD->isStaticLocal())
    return false;

  if (!Analyzed) {
    RunAnalysis();
    Analyzed = true;
  }

  VarDeclSet *NonConstants = (VarDeclSet*)NonConstantsImpl;

  return !NonConstants->count(VD);
}

// Returns true if the variable was used (self assignments don't count)
bool PseudoConstantAnalysis::wasReferenced(const VarDecl *VD) {
  if (!Analyzed) {
    RunAnalysis();
    Analyzed = true;
  }

  VarDeclSet *UsedVars = (VarDeclSet*)UsedVarsImpl;

  return UsedVars->count(VD);
}

void PseudoConstantAnalysis::RunAnalysis() {
  std::deque<const Stmt *> WorkList;
  VarDeclSet *NonConstants = (VarDeclSet*)NonConstantsImpl;
  VarDeclSet *UsedVars = (VarDeclSet*)UsedVarsImpl;

  // Start with the top level statement of the function
  WorkList.push_back(DeclBody);

  while (!WorkList.empty()) {
    const Stmt* Head = WorkList.front();
    WorkList.pop_front();

    switch (Head->getStmtClass()) {
    // Case 1: Assignment operators modifying ValueDecl
    case Stmt::BinaryOperatorClass: {
      const BinaryOperator *BO = cast<BinaryOperator>(Head);
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const DeclRefExpr *DR = dyn_cast<DeclRefExpr>(LHS);

      // We only care about DeclRefExprs on the LHS
      if (!DR)
        break;

      // We found a binary operator with a DeclRefExpr on the LHS. We now check
      // for any of the assignment operators, implying that this Decl is being
      // written to.
      switch (BO->getOpcode()) {
      case BO_Assign: {
        const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
        if (const DeclRefExpr *RHSDecl = dyn_cast<DeclRefExpr>(RHS)) {
          // Self-assignments don't count as use of a variable
          if (DR->getDecl() == RHSDecl->getDecl())
            // Do not visit the children
            continue;
        }

      }
      case BO_AddAssign:
      case BO_SubAssign:
      case BO_MulAssign:
      case BO_DivAssign:
      case BO_AndAssign:
      case BO_OrAssign:
      case BO_XorAssign:
      case BO_ShlAssign:
      case BO_ShrAssign: {
        // The DeclRefExpr is being assigned to - mark it as non-constant
        const VarDecl *VD = dyn_cast<VarDecl>(DR->getDecl());
        if (VD)
          NonConstants->insert(VD);
        break;
      }

      default:
        break;
      }
      break;
    }

    // Case 2: Pre/post increment/decrement and address of
    case Stmt::UnaryOperatorClass: {
      const UnaryOperator *UO = cast<UnaryOperator>(Head);
      const Expr *SubExpr = UO->getSubExpr()->IgnoreParenImpCasts();
      const DeclRefExpr *DR = dyn_cast<DeclRefExpr>(SubExpr);

      // We only care about DeclRefExprs in the subexpression
      if (!DR)
        break;

      // We found a unary operator with a DeclRefExpr as a subexpression. We now
      // check for any of the increment/decrement operators, as well as
      // addressOf.
      switch (UO->getOpcode()) {
      case UO_PostDec:
      case UO_PostInc:
      case UO_PreDec:
      case UO_PreInc:
        // The DeclRefExpr is being changed - mark it as non-constant
      case UO_AddrOf: {
        // If we are taking the address of the DeclRefExpr, assume it is
        // non-constant.
        const VarDecl *VD = dyn_cast<VarDecl>(DR->getDecl());
        if (VD)
          NonConstants->insert(VD);
        break;
      }

      default:
        break;
      }
      break;
    }

    // Case 3: Reference Declarations
    case Stmt::DeclStmtClass: {
      const DeclStmt *DS = cast<DeclStmt>(Head);
      // Iterate over each decl and see if any of them contain reference decls
      for (DeclStmt::const_decl_iterator I = DS->decl_begin(), E = DS->decl_end();
          I != E; ++I) {
        // We only care about VarDecls
        const VarDecl *VD = dyn_cast<VarDecl>(*I);
        if (!VD)
          continue;

        // We found a VarDecl; make sure it is a reference type
        if (!VD->getType().getTypePtr()->isReferenceType())
          continue;

        // If the reference is to another var, add the var to the non-constant
        // list
        if (const DeclRefExpr *DR = dyn_cast<DeclRefExpr>(VD->getInit()))
          if (const VarDecl *RefVD = dyn_cast<VarDecl>(DR->getDecl())) {
            NonConstants->insert(RefVD);
            continue;
          }
      }
      break;
    }

    // Case 4: Block variable references
    case Stmt::BlockDeclRefExprClass: {
      // Any block variables are assumed to be non-constant
      const BlockDeclRefExpr *BDR = cast<BlockDeclRefExpr>(Head);
      if (const VarDecl *VD = dyn_cast<VarDecl>(BDR->getDecl())) {
        NonConstants->insert(VD);
        UsedVars->insert(VD);
        continue;
      }
      break;
    }

    // Case 5: Variable references
    case Stmt::DeclRefExprClass: {
      const DeclRefExpr *DR = cast<DeclRefExpr>(Head);
      if (const VarDecl *VD = dyn_cast<VarDecl>(DR->getDecl())) {
        UsedVars->insert(VD);
        continue;
      }
      break;
    }

      default:
        break;
    } // switch (head->getStmtClass())

    // Add all substatements to the worklist
    for (Stmt::const_child_iterator I = Head->child_begin(),
        E = Head->child_end(); I != E; ++I)
      if (*I)
        WorkList.push_back(*I);
  } // while (!WorkList.empty())
}