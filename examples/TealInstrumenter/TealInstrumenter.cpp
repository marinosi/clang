/*-
 * Copyright (c) 2011 Jonathan Anderson, Steven J. Murdoch
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

/// \file TealInstrumenter and TealAction

#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
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

typedef map< pair<string,string>, string > FieldMap;
typedef map<string, string> FuncInstrMap;

// AST Consumers that instruments specific AST stmts.
class TealInstrumenter : public ASTConsumer {
public:
  TealInstrumenter(StringRef filename,
      vector<FieldMap> fieldsToInstrument,
      vector<FuncInstrMap> functionCallsToInstr,
      vector<FuncInstrMap> functionRetsToInstr);

  // Visitors
  void Visit(DeclContext *dc, ASTContext &ast);
  void Visit(Decl *d, DeclContext *context, ASTContext &ast);
  void Visit(CompoundStmt *cs, FunctionDecl *f, DeclContext* context,
      ASTContext &ast);
  void Visit(Stmt *s, FunctionDecl *f, CompoundStmt *cs, DeclContext* context,
      ASTContext &ast);
  void Visit(Expr *e, FunctionDecl *f, Stmt *s, CompoundStmt *c,
      DeclContext* dc, ASTContext &ast);
  void Visit(
      BinaryOperator *o, Stmt *s, CompoundStmt *cs, DeclContext *dc,
      ASTContext &ast);
  void Visit(
      CallExpr *ce, Stmt *s, CompoundStmt *cs, DeclContext *dc,
      ASTContext &ast);

  // Make 'special' statements more amenable to instrumentation.
  void Prepare(IfStmt *s, ASTContext &ast);
  void Prepare(SwitchCase *s, ASTContext &ast);

  // ASTConsumer implementation.

  virtual void Initialize(ASTContext& ast);

  /// Make note if a tag has been tagged with __teal or the like.
  virtual void HandleTagDeclDefinition(TagDecl *tag);

  /// Recurse down through a declaration of a variable, function, etc.
  virtual void HandleTopLevelDecl(DeclGroupRef d);

  /// We've finished processing an entire translation unit.
  virtual void HandleTranslationUnit(ASTContext &ast);

private:
  /// The file that we're instrumenting.
  StringRef filename;

  /// How many assertions we have already seen in a function.
  map<FunctionDecl*, int> assertionCount;

  template<class T>
  bool contains(const vector<T>& haystack, const T& needle) const {
    return (find(haystack.begin(), haystack.end(), needle) != haystack.end());
  }

  /// Remember that we've added some instrumentation.
  void store(vector<Stmt*> instrumentation);

  /// Do we need to instrument this field?
  bool needToInstrument(const FieldDecl *field) const {
    const RecordDecl *record = field->getParent();
    string base = QualType::getAsString(record->getTypeForDecl(), Qualifiers());
    string fieldname = field->getNameAsString();

    pair <string, string> lemma = make_pair(base, fieldname);

    for ( vector<FieldMap>::const_iterator I = fieldsToInstrument.begin() ; I
            != fieldsToInstrument.end() ; I++ ) {

      FieldMap::const_iterator FD = I->find(lemma);
      if (FD == I->end())
        continue;
      else
        return true;

      //if( contains<string>(FD->second, field->getNameAsString()) )
        //return true;
    }

    return false;
  }

  /// Do we need to instrument this function call/return?
  bool needToInstrument(const vector<FuncInstrMap> FIMapV, const FunctionDecl *f) const {
    if (f == NULL)
      return false;

    for ( vector<FuncInstrMap>::const_iterator I = FIMapV.begin() ; I != FIMapV.end(); I++ ) {
      FuncInstrMap::const_iterator FN;
      FN = I->find(f->getNameAsString());

      if ( FN == I->end())
        continue;
      else
        return true;
    }
    return false;
  }

  /// Emit a warning about inserted instrumentation.
  DiagnosticBuilder warnAddingInstrumentation(SourceLocation) const;

  /// Wrap a non-compound statement in a compound statement
  /// (if the Stmt is already a CompoundStmt, just pass through).
  CompoundStmt* makeCompound(Stmt *s, ASTContext &ast);


  Diagnostic *diag;
  unsigned int tealWarningId;

  const vector<string> typesToInstrument;

  vector<FieldMap> fieldsToInstrument;
  vector<FuncInstrMap> functionCallsToInstr;
  vector<FuncInstrMap> functionRetsToInstr;

  vector<Stmt*> instrumentation;
};

class TealAction : public PluginASTAction {
  protected:
    ASTConsumer *CreateASTConsumer(CompilerInstance &CI, StringRef filename);

    bool ParseArgs(const CompilerInstance &CI, const vector<string>& args);
    void PrintHelp(llvm::raw_ostream& ros);

  private:
    vector<FieldMap> fields;
    vector<FuncInstrMap> function_calls;
    vector<FuncInstrMap> function_rets;
};

static FrontendPluginRegistry::Add<TealAction>
X("teal", "Add TEAL instrumentation");



// ********* TealInstrumenter (still in the anonymous namespace). ********

TealInstrumenter::TealInstrumenter(StringRef filename,
      vector<FieldMap> fieldsToInstrument,
      vector<FuncInstrMap> functionCallsToInstr,
      vector<FuncInstrMap> functionRetsToInstr)
  : filename(filename), fieldsToInstrument(fieldsToInstrument),
    functionCallsToInstr(functionCallsToInstr),
    functionRetsToInstr(functionRetsToInstr)
{
}

void TealInstrumenter::Initialize(ASTContext& ast) {
  diag = &ast.getDiagnostics();
  tealWarningId = diag->getCustomDiagID(
      Diagnostic::Warning, "Adding TEAL instrumentation");
}

void TealInstrumenter::HandleTopLevelDecl(DeclGroupRef d) {
  for (DeclGroupRef::iterator i = d.begin(); i != d.end(); i++) {
    DeclContext *dc = dyn_cast<DeclContext>(*i);
    Visit(*i, dc, (*i)->getASTContext());
  }
}

void TealInstrumenter::HandleTagDeclDefinition(TagDecl *tag) {
  //XXX: This just forwards to HandleTopLevelDecl. Also we don't support
  //attributes with the TealInstrumenter, by that time.
/*
 *  if (tag->getAttr<TealAttr>()) {
 *    assert(isa<RecordDecl>(tag) && "Can't instrument funny tags like enums");
 *    RecordDecl *r = dyn_cast<RecordDecl>(tag);
 *    string typeName = QualType::getAsString(r->getTypeForDecl(), Qualifiers());
 *
 *    typedef RecordDecl::field_iterator FieldIterator;
 *    for (FieldIterator i = r->field_begin(); i != r->field_end(); i++) {
 *      fieldsToInstrument[typeName].push_back((*i)->getName());
 *    }
 */
}

void TealInstrumenter::HandleTranslationUnit(ASTContext &ast) {
}

void TealInstrumenter::Visit(DeclContext *dc, ASTContext &ast) {
  typedef DeclContext::decl_iterator Iterator;
  for (Iterator i = dc->decls_begin(); i != dc->decls_end(); i++) {
    Visit(*i, dc, ast);
  }
}

void TealInstrumenter::Visit(Decl *d, DeclContext *context, ASTContext &ast) {
  // We're not interested in function declarations, only definitions.
  FunctionDecl *f = dyn_cast<FunctionDecl>(d);
  if ((f != NULL) and !f->isThisDeclarationADefinition()) return;

  if (DeclContext *dc = dyn_cast<DeclContext>(d)) {
    Visit(dc, ast);
    context = dc;
  }

  if (d->hasBody()) {
    assert(isa<CompoundStmt>(d->getBody()));
    CompoundStmt *cs = dyn_cast<CompoundStmt>(d->getBody());
    Visit(cs, f, context, ast);
  }
}

void TealInstrumenter::Visit(
    CompoundStmt *cs, FunctionDecl *f, DeclContext* dc, ASTContext &ast) {

  assert(cs != NULL);

  for (StmtRange child = cs->children(); child; child++) {
    // It's perfectly legitimate to have a null child (think an IfStmt with
    // no 'else' clause), but dyn_cast() will choke on it.
    if (*child == NULL) continue;

    if (Expr *e = dyn_cast<Expr>(*child)) Visit(e, f, e, cs, dc, ast);
    else Visit(*child, f, cs, dc, ast);
  }
}

void TealInstrumenter::Visit(
    Stmt *s, FunctionDecl *f, CompoundStmt *cs, DeclContext* dc,
    ASTContext &ast) {

  assert(s != NULL);

  // Special cases that we need to munge a little bit.
  if (IfStmt *i = dyn_cast<IfStmt>(s)) Prepare(i, ast);
  else if (SwitchCase *c = dyn_cast<SwitchCase>(s)) Prepare(c, ast);

  // Now visit the node or its children, as appropriate.
  if (CompoundStmt *c = dyn_cast<CompoundStmt>(s)) Visit(c, f, dc, ast);
  else
    for (StmtRange child = s->children(); child; child++) {
      // It's perfectly legitimate to have a null child (think an IfStmt with
      // no 'else' clause), but dyn_cast() will choke on it.
      if (*child == NULL) continue;

      if (Expr *e = dyn_cast<Expr>(*child)) Visit(e, f, s, cs, dc, ast);
      else Visit(*child, f, cs, dc, ast);
    }
}

void TealInstrumenter::Prepare(IfStmt *s, ASTContext &ast) {
  // For now, simply replace any non-compound then and else clauses with
  // compound versions. We can improve performance through filtering later;
  // right now, we just want to be able to compile more code.
  if (Stmt *t = s->getThen()) s->setThen(makeCompound(t, ast));
  if (Stmt *e = s->getElse()) s->setElse(makeCompound(e, ast));
}

void TealInstrumenter::Prepare(SwitchCase *c, ASTContext &ast) {
  Stmt *sub = c->getSubStmt();
  if (sub == NULL) return;

  // Don't wrap an existing compound statement.
  if (isa<CompoundStmt>(sub)) return;

  // Do wrap a non-compound child.
  CompoundStmt *compound = makeCompound(sub, ast);
  if (CaseStmt *cs = dyn_cast<CaseStmt>(c)) cs->setSubStmt(compound);
  else if (DefaultStmt *d = dyn_cast<DefaultStmt>(c)) d->setSubStmt(compound);
  else
    assert(false && "SwitchCase is neither CaseStmt nor DefaultStmt");
}

void TealInstrumenter::Visit(Expr *e, FunctionDecl *f, Stmt *s,
    CompoundStmt *cs, DeclContext* dc, ASTContext &ast) {

  assert(e != NULL);

  // Otherwise, proceed like normal.
  if (BinaryOperator *o = dyn_cast<BinaryOperator>(e))
    Visit(o, s, cs, f, ast);

  if (CallExpr *ce = dyn_cast<CallExpr>(e))
    Visit(ce, s, cs, f, ast);

  for (StmtRange child = e->children(); child; child++) {
    if (*child == NULL) continue;

    if (Expr *expr = dyn_cast<Expr>(*child)) Visit(expr, f, s, cs, dc, ast);
    else {
      // To have a non-Expr child of an Expr is... odd.
      int id = diag->getCustomDiagID(
          Diagnostic::Warning, "Expression has Non-Expr child");

      diag->Report(id) << e->getSourceRange();

      // XXXIM: The following gets wiped out, at the CPP parsing state so no
      // need to worry about it.
      // The FreeBSD kernel does this kind of thing, though:
#if 0
#define VFS_LOCK_GIANT(MP) __extension__                                \
({                                                                      \
        int _locked;                                                    \
        struct mount *_mp;                                              \
        _mp = (MP);                                                     \
        if (VFS_NEEDSGIANT_(_mp)) {                                     \
                mtx_lock(&Giant);                                       \
                _locked = 1;                                            \
        } else                                                          \
                _locked = 0;                                            \
        _locked;                                                        \
})
#endif

      // Until we figure out exactly what has been segfaulting, we
      // choose to ignore such expressions. Hopefully we never want to
      // instrument them.
//      Visit(s, f, cs, dc, ast);
    }
  }
}

void TealInstrumenter::Visit(
    BinaryOperator *BO, Stmt *S, CompoundStmt *CS, DeclContext *DC,
    ASTContext &AC) {

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

  // CHECK what's the situation at the right hand side.
  //InspectRHS(LHS,RHS);
  if( isa<CallExpr> (RHS)) {
    CallExpr *ce = dyn_cast<CallExpr> (RHS);

    if ( isa<FunctionDecl> (ce->getDirectCallee())) {
      FunctionDecl *F = ce->getDirectCallee();
      if (isa<MemberExpr>(LHS) || isa<DeclRefExpr>(LHS)) {
        vector<Expr *> Params;
        Params.push_back(dyn_cast<Expr>(LHS));

        // Apply the "per automaton" required instrumentation.
        vector<FuncInstrMap>::iterator AM;
        for ( AM = functionRetsToInstr.begin(); AM !=
            functionRetsToInstr.end(); AM++ ) {

          FuncInstrMap::const_iterator FN;
          FN = AM->find(F->getNameAsString());

          // Do we need to instrument the specific function?
          if ( FN == AM->end())
            continue;
          else {
            FunctionCall hook(F, Params, FN->second, DC);
            warnAddingInstrumentation(ce->getLocStart()) <<
              ce->getSourceRange();
            hook.insert_after( S, CS, AC);
          }
        }
      }
    }

  }


  // Handle Left Hand Side of the expression
  if (isa<MemberExpr>(LHS)) {
    MemberExpr *lhs = dyn_cast<MemberExpr>(LHS);
    if (isa <FieldDecl> (lhs->getMemberDecl())) {
      FieldDecl *FD = dyn_cast<FieldDecl> (lhs->getMemberDecl());
      // Apply the "per automaton" required instrumentation.
      vector<FieldMap>::iterator AM;
      for ( AM = fieldsToInstrument.begin(); AM !=
          fieldsToInstrument.end(); AM++ ) {

        string base = QualType::getAsString(FD->getParent()->getTypeForDecl(), Qualifiers());
        string fieldname = FD->getNameAsString();

        // Check if we need to instrument this field.
        pair <string, string> lemma = make_pair(base, fieldname);
        FieldMap::const_iterator I = AM->find(lemma);
        if ( I == AM->end())
          continue;
        else {
          // Need to Instrument.
          FieldAssignment hook(lhs, RHS, I->second, DC);
          warnAddingInstrumentation(BO->getLocStart()) << BO->getSourceRange();
          hook.insert(S, CS, AC);
        }
      }
      //CS->dump();
    } else
      return;
  }


}

void TealInstrumenter::Visit(
    CallExpr *ce, Stmt *s, CompoundStmt *cs, DeclContext *dc,
    ASTContext &ast) {

  if ( isa<FunctionDecl> (ce->getDirectCallee())) {
    FunctionDecl *F = ce->getDirectCallee();

    vector<Expr *> Params;
    CallExpr::arg_iterator AI;
    for ( AI = ce->arg_begin(); AI != ce->arg_end(); ++AI)
      Params.push_back(*AI);

    // Handle Function Calls.
    vector<FuncInstrMap>::iterator AM;
    for ( AM = functionCallsToInstr.begin(); AM != functionCallsToInstr.end();
        AM++ ) {
      FuncInstrMap::const_iterator FN;

      // Check if we need to instrument the function.
      FN = AM->find(F->getNameAsString());
      if ( FN == AM->end())
        continue;
      else {
        FunctionCall hook(F, Params, FN->second, dc);
        warnAddingInstrumentation(ce->getLocStart()) << ce->getSourceRange();
        hook.insert(s, cs, ast);
      }
    }

    // Handle void function calls.
    if ( ce->getCallReturnType()->isVoidType()) {
      // Apply "per automaton" instrumentation.
      for ( AM = functionRetsToInstr.begin(); AM != functionRetsToInstr.end();
          AM++ ) {

        FuncInstrMap::const_iterator FN;

        // Check if we need to instrument the function.
        FN = AM->find(F->getNameAsString());
        if ( FN == AM->end())
          continue;
        else {
          FunctionCall hook(F, Params, FN->second, dc);
          warnAddingInstrumentation(ce->getLocStart()) << ce->getSourceRange();
          hook.insert_after(s, cs, ast);
        }
      }
    }

  }
}

void TealInstrumenter::store(vector<Stmt*> inst) {
  for (vector<Stmt*>::iterator i = inst.begin(); i != inst.end(); i++)
    instrumentation.push_back(*i);
}

CompoundStmt* TealInstrumenter::makeCompound(Stmt *s, ASTContext &ast) {
  // Don't need to nest existing compounds.
  if (CompoundStmt *cs = dyn_cast<CompoundStmt>(s)) return cs;

  SourceLocation loc = s->getLocStart();
  return new (ast) CompoundStmt(ast, &s, 1, loc, loc);
}

DiagnosticBuilder
TealInstrumenter::warnAddingInstrumentation(SourceLocation loc) const {
  return diag->Report(loc, tealWarningId);
}

// ********* TealAction (still in the anonymous namespace). ********

ASTConsumer* TealAction::CreateASTConsumer(CompilerInstance &CI,
    StringRef filename) {
  return new TealInstrumenter(filename, fields, function_calls, function_rets);
}

bool
TealAction::ParseArgs(const CompilerInstance &CI, const vector<string>& args) {


  for (unsigned i = 0, e = args.size(); i != e; ++i) {
    llvm::outs() << "TealInstrumenter arg = " << args[i] << "\n";

    ifstream specFile(args[i].c_str());
    if (!specFile.is_open()) {
      llvm::errs() << "Failed to open spec file '" << args[i] << "'";
      return false;
    }

    // Per Spec file tmp data.
    FieldMap tmp_fields;
    vector<string> tmp_functions;
    FuncInstrMap tmp_function_calls;
    FuncInstrMap tmp_function_rets;

    while (specFile.good()) {
      string line;
      getline(specFile, line);

      // Per Spec file arguments.
      vector<string> spec_args;

      for (size_t i = 0; i != string::npos;) {
        size_t j = line.find(",", i);
        spec_args.push_back(line.substr(i, j - i));

        if (j == string::npos) break;
        i = j + 1;
      }

      if (spec_args.size() == 0) continue;

      if (spec_args[0] == "field_assign") {
        if (spec_args.size() != 4) {
          Diagnostic& diag = CI.getDiagnostics();
          int id = diag.getCustomDiagID(
              Diagnostic::Error,
              "'field_assign' line in spec file should have 3 arguments.");

          diag.Report(id);
          return false;
        }
        pair<string, string> struct_element;
        struct_element = make_pair(spec_args[1], spec_args[2]);

        tmp_fields[struct_element] = spec_args[3];
      } else if (spec_args[0] == "function_call") {
        if (spec_args.size() != 3) {
          Diagnostic& diag = CI.getDiagnostics();
          int id = diag.getCustomDiagID(
              Diagnostic::Error,
              "'function_call' line in spec file should have 2 arguments.");

          diag.Report(id);
          return false;
        }

        tmp_function_calls[spec_args[1]] = spec_args[2];
      } else if (spec_args[0] == "function_ret") {
        if (spec_args.size() != 3) {
          Diagnostic& diag = CI.getDiagnostics();
          int id = diag.getCustomDiagID(
              Diagnostic::Error,
              "'function_ret' line in spec file should have 2 arguments.");

          diag.Report(id);
          return false;
        }

        tmp_function_rets[spec_args[1]] = spec_args[2];
      }

    }

    // Store all the data of each spec file to the universal vectors that will
    // be passed to the actual AST Consumer (TealInstrumenter).
    fields.push_back(tmp_fields);
    function_calls.push_back(tmp_function_calls);
    function_rets.push_back(tmp_function_rets);

  }
  return true;
}

void TealAction::PrintHelp(llvm::raw_ostream& ros) {
  ros << "TealInstrumenter usage: -plugin teal -plugin-arg-teal <spec file>\n";
}

}
