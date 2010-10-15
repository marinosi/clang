//===--- CodeGenTypes.cpp - TBAA information for LLVM CodeGen -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This is the code that manages TBAA information.
//
//===----------------------------------------------------------------------===//

#include "CodeGenTBAA.h"
#include "Mangle.h"
#include "clang/AST/ASTContext.h"
#include "llvm/LLVMContext.h"
#include "llvm/Metadata.h"
using namespace clang;
using namespace CodeGen;

CodeGenTBAA::CodeGenTBAA(ASTContext &Ctx, llvm::LLVMContext& VMContext,
                         const LangOptions &Features, MangleContext &MContext)
  : Context(Ctx), VMContext(VMContext), Features(Features), MContext(MContext),
    Root(0), Char(0) {
}

CodeGenTBAA::~CodeGenTBAA() {
}

llvm::MDNode *CodeGenTBAA::getTBAAInfoForNamedType(llvm::StringRef NameStr,
                                                   llvm::MDNode *Parent) {
  llvm::Value *Ops[] = {
    llvm::MDString::get(VMContext, NameStr),
    Parent
  };

  return llvm::MDNode::get(VMContext, Ops, llvm::array_lengthof(Ops));
}

llvm::MDNode *
CodeGenTBAA::getTBAAInfo(QualType QTy) {
  Type *Ty = Context.getCanonicalType(QTy).getTypePtr();

  if (llvm::MDNode *N = MetadataCache[Ty])
    return N;

  if (!Root) {
    Root = getTBAAInfoForNamedType("Experimental TBAA", 0);
    Char = getTBAAInfoForNamedType("omnipotent char", Root);
  }

  // For now, just emit a very minimal tree.
  if (const BuiltinType *BTy = dyn_cast<BuiltinType>(Ty)) {
    switch (BTy->getKind()) {
    // Character types are special and can alias anything.
    // In C++, this technically only includes "char" and "unsigned char",
    // and not "signed char". In C, it includes all three. For now,
    // the risk of exploiting this detail in C++ seems likely to outweigh
    // the benefit.
    case BuiltinType::Char_U:
    case BuiltinType::Char_S:
    case BuiltinType::UChar:
    case BuiltinType::SChar:
      return Char;

    // Unsigned types can alias their corresponding signed types.
    case BuiltinType::UShort:
      return getTBAAInfo(Context.ShortTy);
    case BuiltinType::UInt:
      return getTBAAInfo(Context.IntTy);
    case BuiltinType::ULong:
      return getTBAAInfo(Context.LongTy);
    case BuiltinType::ULongLong:
      return getTBAAInfo(Context.LongLongTy);
    case BuiltinType::UInt128:
      return getTBAAInfo(Context.Int128Ty);

    // Treat all other builtin types as distinct types. This includes
    // treating wchar_t, char16_t, and char32_t as distinct from their
    // "underlying types".
    default:
      return MetadataCache[Ty] =
               getTBAAInfoForNamedType(BTy->getName(Features), Char);
    }
  }

  // TODO: Implement C++'s type "similarity" and consider dis-"similar"
  // pointers distinct.
  if (Ty->isPointerType())
    return MetadataCache[Ty] = getTBAAInfoForNamedType("any pointer", Char);

  // Enum types are distinct types. In C++ they have "underlying types",
  // however they aren't related for TBAA.
  if (const EnumType *ETy = dyn_cast<EnumType>(Ty)) {
    // In C mode, two anonymous enums are compatible iff their members
    // are the same -- see C99 6.2.7p1. For now, be conservative. We could
    // theoretically implement this by combining information about all the
    // members into a single identifying MDNode.
    if (!Features.CPlusPlus &&
        ETy->getDecl()->getTypedefForAnonDecl())
      return MetadataCache[Ty] = Char;

    // In C++ mode, types have linkage, so we can rely on the ODR and
    // on their mangled names, if they're external.
    // TODO: Is there a way to get a program-wide unique name for a
    // decl with local linkage or no linkage?
    if (Features.CPlusPlus &&
        ETy->getDecl()->getLinkage() != ExternalLinkage)
      return MetadataCache[Ty] = Char;

    // TODO: This is using the RTTI name. Is there a better way to get
    // a unique string for a type?
    llvm::SmallString<256> OutName;
    MContext.mangleCXXRTTIName(QualType(ETy, 0), OutName);
    return MetadataCache[Ty] = getTBAAInfoForNamedType(OutName, Char);
  }

  // For now, handle any other kind of type conservatively.
  return MetadataCache[Ty] = Char;
}