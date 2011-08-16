/*-
 * Copyright (c) 2011 Ilias Marinos
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
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
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

/// \file DtraceInstrumenter and DtraceAction

#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ParentMap.h"
#include "clang/Frontend/CompilerInstance.h"

#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/raw_os_ostream.h"

#include <fstream>
#include <map>
#include <set>
#include <sstream>

#include "Instrumentation.h"

using namespace clang;
using namespace std;

using llvm::StringRef;

namespace {

typedef map<const RecordDecl *, vector<string> > FieldMap;
typedef map<const DeclContext *, vector<string> > VariableMap;

class DtraceInstrumenter : public ASTConsumer {
public:
  DtraceInstrumenter();

  // ASTConsumer implementation.

  virtual void Initialize(ASTContext& ast);

  /// Make note if a tag has been tagged with __instrument or the like.
  /// This originally forwards to HandleTopLevelDecl().
  virtual void HandleTagDeclDefinition(TagDecl *tag);

  /// Recurse down through a declaration of a variable, function, etc.
  virtual void HandleTopLevelInstrumentDecl(DeclGroupRef DG);

  /// Recurse down through a declaration of a variable, function, etc.
  virtual void HandleTopLevelDecl(DeclGroupRef DG);

  // Recurse down through each declaration within a declaration Context.
  void HandleTopLevelDeclContext(DeclContext *DC);

  // Handle top level single declarations.
  void HandleTopLevelSingleDecl(Decl *D, DeclContext *DC);

  // Gather the dtrace annotated bits.
  void HandleDtraceSingleDecl(FunctionDecl *F, DeclContext *DC);
  void HandleDtraceSingleDecl(FieldDecl *FD, DeclContext *DC);
  void HandleDtraceSingleDecl(VarDecl *V, DeclContext *DC);

  /// We've finished processing an entire translation unit.
  virtual void HandleTranslationUnit(ASTContext &ast);

  // Visitors
  void VisitDeclContext(DeclContext *DC);
  void VisitDecl(Decl *D, DeclContext *DC);
  void VisitFunctionDecl(FunctionDecl *F, DeclContext *DC);
  void VisitCompoundStmt(CompoundStmt *CS, DeclContext *DC, ASTContext &AC);
  void VisitStmt(Stmt *S, CompoundStmt *CS, DeclContext *DC, ASTContext &AC);
  void VisitBinaryOperator(BinaryOperator *BO, CompoundStmt *CS, DeclContext *DC,
          ASTContext &AC);
  void VisitCallExpr(CallExpr *CE, DeclContext *DC);

  // Inspect RHS
  void InspectRHS(Expr *LHS, Expr *RHS);

  // Register bits for instrumentation.
  void RegisterInstr(Decl *D);

private:
  template<class T>
  bool contains(const vector<T>& haystack, const T& needle) const {
	return (find(haystack.begin(), haystack.end(), needle) != haystack.end());
  }

  /// Do we need to instrument this function?
  bool needToInstrument(const FunctionDecl *f) const {
	if (f == NULL) return false;
	return contains<string>(functionsToInstrument, f->getNameAsString());
  }

  /// Do we need to instrument this variable?
  bool needToInstrument(const VarDecl *var) const {
	const DeclContext *dc = var->getDeclContext();

	VariableMap::const_iterator i = variablesToInstrument.find(dc);
	if (i == variablesToInstrument.end()) return false;

	return contains<string>(i->second, var->getNameAsString());
  }

  /// Do we need to instrument this field?
  bool needToInstrument(const FieldDecl *field) const {
	const RecordDecl *record = field->getParent();

	FieldMap::const_iterator i = fieldsToInstrument.find(record);
	if (i == fieldsToInstrument.end()) return false;

	return contains<string>(i->second, field->getNameAsString());
  }

  /// Emit a warning about inserted instrumentation.
  DiagnosticBuilder warnAddingInstrumentation(SourceLocation) const;

  // Diagnostics.
  Diagnostic *diag;
  unsigned int warningId;

  // Instrumentation categories.
  VariableMap variablesToInstrument;
  FieldMap fieldsToInstrument; // Type elements to probe.
  const vector<string> typesToInstrument; // Do we need that?
  const vector<string> functionsToInstrument; // Do we need that?

  vector<Stmt*> instrumentation;

};


class DtraceAction : public PluginASTAction {
  protected:
	ASTConsumer *CreateASTConsumer(CompilerInstance &CI, StringRef filename);

	bool ParseArgs(const CompilerInstance &CI, const vector<string>& args);
	void PrintHelp(llvm::raw_ostream& ros);

  private:
	map<string, vector<string> > fields;
	vector<string> functions;
};

static FrontendPluginRegistry::Add<DtraceAction>
X("dtrace", "Add Dtrace instrumentation");



// ********* DtraceInstrumenter (still in the anonymous namespace). ********

DtraceInstrumenter::DtraceInstrumenter() {
}

void DtraceInstrumenter::Initialize(ASTContext& AC) {
  diag = &AC.getDiagnostics();
  warningId = diag->getCustomDiagID(
	  Diagnostic::Warning, "Adding instrumentation");
}

void DtraceInstrumenter::HandleTopLevelInstrumentDecl(DeclGroupRef DG) {
	// XXX: Is this needed ?
}

void DtraceInstrumenter::HandleTopLevelDecl(DeclGroupRef DG) {
	//llvm::outs() << "Inside HandleTopLevelDecl\n";
	// XXX: Perhaps this is not needed -- check ParseAST.cpp.
	if ( DG.isNull() )
		return;
	for (DeclGroupRef::iterator I = DG.begin(); I != DG.end(); I++)
		// XXXIM: Can the iterator point to NULL at some case?
		if (*I) {
			//DeclContext *dc = dyn_cast<DeclContext>(*I);
			// Is this a declaration context?
			if(DeclContext *dc = dyn_cast<DeclContext> (*I))
				HandleTopLevelDeclContext(dc);
			else
				HandleTopLevelSingleDecl((*I), (*I)->getDeclContext());
		}
}

void DtraceInstrumenter::HandleTopLevelDeclContext(DeclContext *DC) {
	//llvm::outs() << "Inside Function " << __FUNCTION__ << "\n";
	typedef DeclContext::decl_iterator Iterator;
	for (Iterator I = DC->decls_begin(); I != DC->decls_end(); I++ ) {
        // Recursive call of this method in case of a DeclContext inside a
        // DeclContext (e.g struct in a function).
        if (DeclContext *dc = dyn_cast<DeclContext> (*I))
            HandleTopLevelDeclContext(dc);
        else if (*I)
			HandleTopLevelSingleDecl((*I), DC);
    }
}

void DtraceInstrumenter::HandleTopLevelSingleDecl(Decl *D, DeclContext *DC) {

	if(isa<DeclContext>(D))
		llvm::errs() << "Is this ok?!\n";

	// XXXIM: The dtrace attribute is limited and cannot apply to
	// definitions, only to declarations. As such every time we are finding
	// this attribute will be the original declaration(at least for AnsiC).
	// XXX: Remember to check for situations like int a, b;

    // lib/Sema/SemaDeclAttr.cpp
	if (D->getAttr<DtraceAttr>()) {
		// XXX: Find out what kind of declaration we have.
		// We need to expand this as much as possible to meet C-related
		// declarations only.
		// http://clang.llvm.org/doxygen/classclang_1_1Decl.html

		if (isa<DeclaratorDecl>(D)) {
			if(isa<FunctionDecl>(D))
				llvm::errs() << "We cannot handle functions at the moment!\n";
				//HandleDtraceSingleDecl(dyn_cast<FunctionDecl>(D));
			else if (isa<VarDecl>(D))
				HandleDtraceSingleDecl(dyn_cast<VarDecl> (D), DC);
			else if (isa<FieldDecl>(D)) {
				HandleDtraceSingleDecl(dyn_cast<FieldDecl> (D), DC);
			} else {
				llvm::errs() << "No other DeclaratorDecl derivative is \
				interesting for instrumentation";
				return;
			}
		}
	}
}

void DtraceInstrumenter::HandleDtraceSingleDecl(FunctionDecl *D, DeclContext *DC) {
	// XXXIM: Nothing here.

}

void DtraceInstrumenter::HandleDtraceSingleDecl(FieldDecl *D, DeclContext *DC) {
	// XXXIM: Nothing here.
    RegisterInstr(dyn_cast<Decl> (D));
}

void DtraceInstrumenter::HandleDtraceSingleDecl(VarDecl *D, DeclContext *DC) {
	// XXXIM: Nothing here.
	if (D->isExternC())
		; // Find out what to do here.
	if (D->isFileVarDecl())
		;
	// Push the variable name within the context var vector.
    RegisterInstr(dyn_cast<Decl> (D));

}

void DtraceInstrumenter::HandleTagDeclDefinition(TagDecl *tag) {
	// This forwards by default to HandleTopLevelDecl()

	/*
	 *if (tag->getAttr<DtraceAttr>()) {
	 *	// XXXIM: Do we have to allow dtrace annotated types(e.g structs, unions)?
	 *	llvm::outs() << "Found dtrace tag.\n";
	 *}
	 */
}

void DtraceInstrumenter::HandleTranslationUnit(ASTContext &AC) {

	TranslationUnitDecl *TU = AC.getTranslationUnitDecl();
	DeclContext::decl_iterator I;
	for ( I = TU->decls_begin(); I != TU->decls_end(); I++) {
			VisitDecl((*I), (*I)->getDeclContext());
	}

}

void DtraceInstrumenter::VisitDecl(Decl *D, DeclContext *DC) {

	// If it is a function, do we need
	if ( isa<FunctionDecl> (D)) {
		FunctionDecl *f = dyn_cast<FunctionDecl>(D);
        // Check the parameters of a function so that we cannot lose track of
        // variables, fields we ought to monitor. Remember the problem when
        // using iterators and transforming AST.
        /*
         *FunctionDecl::param_iterator P;
         *for ( P = f->param_begin() ; P != f->param_end() ; P++) {
         *    if ( isa<VarDecl> (*P) ) {
         *        VarDecl *VD = dyn_cast<VarDecl> (*P);
         *        if (needToInstrument(VD))
         *            llvm::outs() << "This is nasty!\n";
         *    }
         *}
         */


		if ( !f->isThisDeclarationADefinition() )
			return;
		VisitFunctionDecl(f, DC);


	}

}

void DtraceInstrumenter::VisitFunctionDecl(FunctionDecl *F,
		DeclContext *DC) {

	CompoundStmt *cs;
	if ( F->hasBody() ) {
		//llvm::outs() << F->getNameAsString() << " function has body!\n";
		if ( isa<CompoundStmt> (F->getBody()) ) {

            //ParentMap StmtTree(F->getBody());
			cs = dyn_cast<CompoundStmt>(F->getBody());

			if (needToInstrument(F)) {
				// Not Implemented.
			}
	        VisitCompoundStmt(cs, DC, F->getASTContext());
		}

	}
}

void DtraceInstrumenter::VisitCompoundStmt(CompoundStmt *CS,
		DeclContext *DC, ASTContext &AC) {
	// If Compound Statement is empty, return.
	if ( CS->body_empty() )
		return;

    // XXX: Nasty bits here. If you are using the normal iterator to go
    // through one Compound Statement's statements and you modify AST in the
    // meantime, this will lead to a silent Null Dereference :).
    /*
     *CompoundStmt::body_iterator I;
     *for ( I = CS->body_begin(); I != CS->body_end(); I++ )
     *        VisitStmt(*I, CS, DC, ASTC);
     */

    for (StmtRange child = CS->children(); child; child++) {
        // It's perfectly legitimate to have a null child (think an IfStmt with
        // no 'else' clause), but dyn_cast() will choke on it.
        if (*child == NULL)
            continue;

        VisitStmt(*child, CS, DC, AC);
    }
}

void DtraceInstrumenter::VisitStmt(Stmt *S, CompoundStmt *CS,
		DeclContext *DC, ASTContext &AC) {
	// http://clang.llvm.org/doxygen/classclang_1_1Stmt.html

    /*
     *if (isa <CompoundStmt> (S))
     *    VisitCompoundStmt(dyn_cast<CompoundStmt> (S), DC, AC);
	 *if (isa <Expr> (S)) {
	 *    if (isa <BinaryOperator>(S))
	 *        // Something different for CompoundAssignOperator(?).
	 *        VisitBinaryOperator(dyn_cast<BinaryOperator> (S), CS, DC, AC);
     *    if (isa <CallExpr>(S))
     *        VisitCallExpr(dyn_cast<CallExpr> (S), DC);
     *}
     */

  // Special cases that we need to munge a little bit.
  /*
   *if( isa<IfStmt> (S))
   *  Prepare(dyn_cast<IfStmt> (S), AC);
   *if( isa<SwitchCase> (S))
   *  Prepare(dyn_cast<SwitchCase> (S), AC);
   */

  // Now check if it is a CompoundStmt or ReturnStmt.
  if (isa <CompoundStmt> (S))
    VisitCompoundStmt(dyn_cast<CompoundStmt> (S), DC, AC);
  else if (isa <BinaryOperator> (S))
    VisitBinaryOperator( dyn_cast<BinaryOperator> (S), CS, DC, AC);
  else
    for (StmtRange child = S->children(); child; child++) {
      // It's perfectly legitimate to have a null child (think an IfStmt with
      // no 'else' clause), but dyn_cast() will choke on it.
      if (*child == NULL) continue;

      if ( isa<BinaryOperator> (*child))
        VisitBinaryOperator(dyn_cast<BinaryOperator> (*child), CS, DC, AC);
      else
        VisitStmt(*child, CS, DC, AC);
    }

}

void DtraceInstrumenter::VisitBinaryOperator(BinaryOperator *BO,
		CompoundStmt *CS, DeclContext *DC, ASTContext &AC) {

  if (!BO->isAssignmentOp()) return;

  switch (BO->getOpcode()) {
    case BO_Assign:
    case BO_MulAssign:
    case BO_DivAssign:
    case BO_RemAssign:
    case BO_AddAssign:
    case BO_SubAssign:
    case BO_ShlAssign:
    case BO_ShrAssign:
    case BO_AndAssign:
    case BO_XorAssign:
    case BO_OrAssign:
      break;

    default:
      assert(false && "isBinaryInstruction() => non-assign opcode");
  }

  // Get the left & right hand side.
  Expr *LHS = BO->getLHS();
  Expr *RHS = BO->getRHS();

  // XXX: QUITE TRICKY!
  // CHECK what's the situation at the right hand side.
  InspectRHS(LHS,RHS);

  // Handle Left Hand Side of the expression
  if (isa<MemberExpr>(LHS)) {
    MemberExpr *lhs = dyn_cast<MemberExpr>(LHS);
    if (isa <FieldDecl> (lhs->getMemberDecl())) {
      FieldDecl *FD = dyn_cast<FieldDecl> (lhs->getMemberDecl());
      if (needToInstrument(FD)) {
        //XXX: Apply instrumentation or rewrites here.
        FieldAssignment hook(lhs, RHS, DC);
        warnAddingInstrumentation(BO->getLocStart()) << BO->getSourceRange();
        hook.insert(dyn_cast<Stmt> (BO), CS, AC);
        //CS->dump();
      }
    } else
      return;
  }

  if (isa<DeclRefExpr>(LHS)) {
    DeclRefExpr *lhs = dyn_cast<DeclRefExpr>(LHS);
    if (isa <VarDecl> (lhs->getDecl())) {
      VarDecl *VD = dyn_cast<VarDecl> (lhs->getDecl());
      if (needToInstrument(VD)) {
        //XXX: Apply instrumentation or rewrites here.
        VarAssignment hook(lhs, RHS, DC);
        warnAddingInstrumentation(BO->getLocStart())
          << BO->getSourceRange();
        hook.insert_after(dyn_cast<Stmt> (BO), CS, AC);
      }
    } else
      return;
  }

  Expr *LE;
  if (isa<UnaryOperator>(LHS)) {
    UnaryOperator *UO = dyn_cast<UnaryOperator> (LHS);
    LE = UO->getSubExpr();
    if (isa<ImplicitCastExpr> (LE)) {

      ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr> (LE);
      Expr *SE = ICE->getSubExpr();
      if (isa<DeclRefExpr>(SE)) {
        DeclRefExpr *lhs = dyn_cast<DeclRefExpr>(SE);
        if (isa <VarDecl> (lhs->getDecl())) {
          VarDecl *VD = dyn_cast<VarDecl> (lhs->getDecl());
          if (needToInstrument(VD)) {
            //XXX: Apply instrumentation or rewrites here.
            VarAssignment hook(lhs, RHS, DC);
            warnAddingInstrumentation(BO->getLocStart())
              << BO->getSourceRange();
            hook.insert_after(dyn_cast<Stmt> (BO), CS, AC);
          }
        } else
          return;
      }

    }
  }
}

void DtraceInstrumenter::VisitCallExpr(CallExpr *CE,
		DeclContext *DC) {

    // Not implemented yet
    return;

}

void DtraceInstrumenter::InspectRHS ( Expr *LHS, Expr *RHS ) {

    bool instrumentLHS = false;

    // Get the RHS subexpression, if any.
    Expr *RE;

    if (isa<UnaryOperator>(RHS)) {
        UnaryOperator *UO = dyn_cast<UnaryOperator> (RHS);
        RE = UO->getSubExpr();
    } else if (isa<CastExpr>(RHS)) {
        CastExpr *CAE = dyn_cast<CastExpr> (RHS);
        RE = CAE->getSubExpr();
    } else
        return;

    // XXX: Handle Right Hand Side of the expression
	if (isa<MemberExpr>(RE)) {
		MemberExpr *rhs = dyn_cast<MemberExpr>(RE);
		if (isa <FieldDecl> (rhs->getMemberDecl())) {
			FieldDecl *FD = dyn_cast<FieldDecl> (rhs->getMemberDecl());
			if (needToInstrument(FD) && LHS->getType()->isPointerType() )
                instrumentLHS = true;
        }
	}

	if (isa<DeclRefExpr>(RE)) {
		DeclRefExpr *rhs = dyn_cast<DeclRefExpr>(RE);
		if (isa <VarDecl> (rhs->getDecl())) {
			VarDecl *VD = dyn_cast<VarDecl> (rhs->getDecl());
			if (needToInstrument(VD) && LHS->getType()->isPointerType() )
                instrumentLHS = true;
        }
	}


    if ( instrumentLHS ) {
		if (isa<MemberExpr>(LHS)) {
			MemberExpr *lhs = dyn_cast<MemberExpr>(LHS);
			if (isa <FieldDecl> (lhs->getMemberDecl())) {
				FieldDecl *FD = dyn_cast<FieldDecl> (lhs->getMemberDecl());
				if (!needToInstrument(FD))
                    RegisterInstr(dyn_cast<Decl> (FD));
			} else
				return;
		}

		if (isa<DeclRefExpr>(LHS)) {
			DeclRefExpr *lhs = dyn_cast<DeclRefExpr>(LHS);
			if (isa <VarDecl> (lhs->getDecl())) {
				VarDecl *VD = dyn_cast<VarDecl> (lhs->getDecl());
				if (!needToInstrument(VD))
                    RegisterInstr(dyn_cast<Decl> (VD));
			} else
				return;
		}
    }
}

void DtraceInstrumenter::RegisterInstr( Decl *D ) {

    if ( isa<VarDecl> (D) ) {
        VarDecl *vd = dyn_cast<VarDecl> (D);
	    variablesToInstrument[vd->getDeclContext()].push_back(vd->getNameAsString());
        return;
    }
    if ( isa<FieldDecl> (D) ) {
        FieldDecl *fd = dyn_cast<FieldDecl> (D);
	    fieldsToInstrument[fd->getParent()].push_back(fd->getNameAsString());
        return;
    }
}


DiagnosticBuilder
DtraceInstrumenter::warnAddingInstrumentation(SourceLocation loc) const {
  return diag->Report(loc, warningId);
}

// ********* DtraceAction (still in the anonymous namespace). ********
ASTConsumer* DtraceAction::CreateASTConsumer(CompilerInstance &CI,
	StringRef filename) {
  return new DtraceInstrumenter();
}

bool
DtraceAction::ParseArgs(const CompilerInstance &CI,
		const vector<string>& args) {
  if (args.size() >= 1) {
	PrintHelp(llvm::errs());
	return false;
  }
  return true;
}

void DtraceAction::PrintHelp(llvm::raw_ostream& ros) {
  ros << "dtrace usage: -plugin dtrace\n";
}

}
