#ifndef __MINGW_ASSERT_H_INCLUDED
#define __MINGW_ASSERT_H_INCLUDED
/* all files must include this header */
#include <_mingw.h>
#ifdef NDEBUG
#  ifndef assert
#    define assert(_Expression) ((void)0)
#  endif /* assert */
#else
#  ifdef __cplusplus
extern "C" {
#  endif
extern void __cdecl _wassert(
    const wchar_t *_Message,
    const wchar_t *_File,
    unsigned _Line
);
#  ifdef __cplusplus
}
#  endif
#  ifndef assert
#    define assert(_Expression) (void)((!!(_Expression)) || \
     (_wassert(_CRT_WIDE(#_Expression),_CRT_WIDE(__FILE__),__LINE__),0))
#  endif
#endif /* NDEBUG */
#endif /* __MINGW_ASSERT_H_INCLUDED */
