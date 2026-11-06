#pragma once
#include "../include/ApplicationRoutingPolicy.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
namespace furious::wfp::policy {
enum class ValidationResult { Valid, NullPolicy, HeaderTooSmall, InvalidTotalSize, UnsupportedAbi, TooManyRules, InvalidBackend, InvalidRuleSize, InvalidEnabledFlag, InvalidAction, InvalidPathLength, PathNotAbsolute, PathContainsInvalidCharacter, DuplicatePriority, DuplicateImagePath };
inline bool IsAbsoluteWindowsPath(const wchar_t* p, uint32_t n) noexcept {
 if (!p || n < 3) return false;
 const bool drive=((p[0]>=L'A'&&p[0]<=L'Z')||(p[0]>=L'a'&&p[0]<=L'z'))&&p[1]==L':'&&(p[2]==L'\\'||p[2]==L'/');
 return drive || (n>=5 && p[0]==L'\\' && p[1]==L'\\');
}
inline bool EqualPathInsensitive(const wchar_t* a,const wchar_t* b) noexcept {
 for(;*a&&*b;++a,++b){wchar_t x=*a,y=*b;if(x>=L'A'&&x<=L'Z')x+=L'a'-L'A';if(y>=L'A'&&y<=L'Z')y+=L'a'-L'A';if(x!=y)return false;} return *a==*b;
}
inline ValidationResult ValidatePolicy(const void* data,size_t bytes) noexcept {
 if(!data)return ValidationResult::NullPolicy;
 if(bytes<sizeof(FURIOUS_WFP_POLICY_HEADER))return ValidationResult::HeaderTooSmall;
 FURIOUS_WFP_POLICY_HEADER h={};const auto* raw=static_cast<const uint8_t*>(data);auto* dst=reinterpret_cast<uint8_t*>(&h);
 for(size_t i=0;i<sizeof(h);++i)dst[i]=raw[i];
 if(h.Size!=sizeof(h)||h.AbiVersion!=FURIOUS_WFP_POLICY_ABI_VERSION)return ValidationResult::UnsupportedAbi;
 if(h.RuleCount>FURIOUS_WFP_MAX_RULES)return ValidationResult::TooManyRules;
 if(h.Backend>FuriousWfpBackendTun2socks)return ValidationResult::InvalidBackend;
 const size_t expected=sizeof(h)+static_cast<size_t>(h.RuleCount)*sizeof(FURIOUS_WFP_APPLICATION_RULE);
 if(expected<sizeof(h)||expected!=bytes)return ValidationResult::InvalidTotalSize;
 for(uint32_t i=0;i<h.RuleCount;++i){FURIOUS_WFP_APPLICATION_RULE r={};std::memcpy(&r,raw+sizeof(h)+static_cast<size_t>(i)*sizeof(r),sizeof(r));
  if(r.Size!=sizeof(FURIOUS_WFP_APPLICATION_RULE))return ValidationResult::InvalidRuleSize;
  if(r.Enabled>1)return ValidationResult::InvalidEnabledFlag;
  if(r.Action!=FuriousWfpActionProxy&&r.Action!=FuriousWfpActionDirect)return ValidationResult::InvalidAction;
  if(r.ImagePathChars<3||r.ImagePathChars>=FURIOUS_WFP_MAX_IMAGE_PATH_CHARS||r.ImagePath[r.ImagePathChars]!=L'\0')return ValidationResult::InvalidPathLength;
  for(uint32_t c=0;c<r.ImagePathChars;++c){const wchar_t ch=r.ImagePath[c];if(ch==L'\0'||ch<0x20||ch==L'*'||ch==L'?')return ValidationResult::PathContainsInvalidCharacter;}
  if(!IsAbsoluteWindowsPath(r.ImagePath,r.ImagePathChars))return ValidationResult::PathNotAbsolute;
  for(uint32_t j=0;j<i;++j){FURIOUS_WFP_APPLICATION_RULE previous={};std::memcpy(&previous,raw+sizeof(h)+static_cast<size_t>(j)*sizeof(previous),sizeof(previous));if(previous.Priority==r.Priority)return ValidationResult::DuplicatePriority;if(EqualPathInsensitive(previous.ImagePath,r.ImagePath))return ValidationResult::DuplicateImagePath;}
 }
 return ValidationResult::Valid;
}
} // namespace furious::wfp::policy
