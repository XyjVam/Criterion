/*
 * The MIT License (MIT)
 *
 * Copyright © 2016 Franklin "Snaipe" Mathieu <http://snai.pe/>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#ifndef CRITERION_INTERNAL_NEW_ASSERTS_H_
#define CRITERION_INTERNAL_NEW_ASSERTS_H_

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>

#include "asprintf-compat.h"
#include "common.h"
#include "designated-initializer-compat.h"
#include "preprocess.h"

enum cri_assert_result_type {
    CRI_ASSERT_RT_NONE = 0,
    CRI_ASSERT_RT_DATA,
    CRI_ASSERT_RT_FILE,

    CRI_ASSERT_RT_STRING = 1 << 8 | CRI_ASSERT_RT_DATA,
};

struct cri_assert_node {
    const char *repr;
    void *expected;
    void *actual;
    int pass;
    enum cri_assert_result_type rtype;
    size_t nchild;
    size_t maxchild;
    struct cri_assert_node *children;
};

CR_BEGIN_C_API

CR_API void cri_assert_node_init(struct cri_assert_node *node);
CR_API struct cri_assert_node *cri_assert_node_add(struct cri_assert_node *tree,
        struct cri_assert_node *node);
CR_API void cri_assert_node_negate(struct cri_assert_node *tree);
CR_API void cri_assert_node_term(struct cri_assert_node *tree);
CR_API void cri_assert_node_send(const char *file, size_t line, struct cri_assert_node *tree);
CR_API char *cri_assert_message(const char *fmt, ...);

CR_END_C_API

#define CRI_SPECIFIER_INDIRECT()      CRI_ASSERT_SPECIFIER

#define CRI_ASSERT_SPECIFIER(Spec)    CRI_IF_DEFINED(CRI_ASSERT_TEST_SPECIFIER_ ## Spec, CR_CONCAT2, (CRI_ASSERT_SPECIFIER_, Spec), CRI_ASSERT_SPECIFIER_VALUE, (Spec))

#define CRI_ASSERT_FAIL(File, Line, Fail, ...)                           \
    CR_EVAL(do {                                                         \
        struct cri_assert_node cri_root, *cri_node = &cri_root;          \
        cri_assert_node_init(&cri_root);                                 \
        cri_root.repr = cri_assert_message("x" CR_VA_TAIL(__VA_ARGS__)); \
        cri_assert_node_send(File, Line, &cri_root);                     \
        Fail();                                                          \
    } while (0))

#define CRI_ASSERT_CALL(File, Line, Fail, Condition, ...)                    \
    CR_EVAL(do {                                                             \
        struct cri_assert_node cri_tmpn, cri_root, *cri_node = &cri_root;    \
        (void) cri_tmpn;                                                     \
        (void) cri_node;                                                     \
        cri_assert_node_init(&cri_root);                                     \
        int cri_cond, cri_cond_un, *cri_pass = &cri_cond_un;                 \
        int cri_cond_def = 1;                                                \
        (void) cri_cond_def;                                                 \
        (void) cri_pass;                                                     \
        cri_cond_un = CRI_ASSERT_SPECIFIER(Condition);                       \
        cri_cond = cri_cond_un;                                              \
        if (!cri_cond) {                                                     \
            cri_root.repr = cri_assert_message("x" CR_VA_TAIL(__VA_ARGS__)); \
            cri_assert_node_send(File, Line, &cri_root);                     \
        }                                                                    \
        if (!cri_cond)                                                       \
            Fail();                                                          \
    } while (0))

#define CRI_ASSERT_TYPE_TAG(Tag)           CR_EXPAND(CRI_ASSERT_TYPE_TAG_(Tag))
#define CRI_ASSERT_TYPE_TAG_(Tag)          CRI_IF_DEFINED(CRI_ASSERT_TEST_TAG_ ## Tag, CRI_ASSERT_TYPE_TAG_ ## Tag, , CRI_ASSERT_TYPE_TAG_USER, (Tag))

#define CRI_USER_TAG_ID(Id, Tag)           CR_CONCAT(cr_user_ ## Id ## _, CRI_ASSERT_TYPE_TAG_ID(Tag))

#define CRI_ASSERT_TYPE_TAG_ID(Tag)        CR_EXPAND(CRI_ASSERT_TYPE_TAG_ID_(Tag))
#define CRI_ASSERT_TYPE_TAG_ID_(Tag)       CRI_IF_DEFINED_NODEFER(CRI_ASSERT_TEST_TAG_ ## Tag, Tag, , CRI_ASSERT_SWALLOW_KEYWORD, (Tag))

#define CRI_ASSERT_TYPE_TAG_USER(Tag)      Tag

#define CRI_ASSERT_SWALLOW_KEYWORD(Tag)    CRI_IF_DEFINED(CRI_ASSERT_TEST_KW_ ## Tag, CRI_ASSERT_SWALLOW_KW_ ## Tag, , Tag, )
#define CRI_ASSERT_TEST_KW_struct    ,
#define CRI_ASSERT_SWALLOW_KW_struct
#define CRI_ASSERT_TEST_KW_class     ,
#define CRI_ASSERT_SWALLOW_KW_class
#define CRI_ASSERT_TEST_KW_enum      ,
#define CRI_ASSERT_SWALLOW_KW_enum
#define CRI_ASSERT_TEST_KW_union     ,
#define CRI_ASSERT_SWALLOW_KW_union

#define CRI_ASSERT_TEST_TAG_i8        ,
#define CRI_ASSERT_TYPE_TAG_i8        int8_t

#define CRI_ASSERT_TEST_TAG_i16       ,
#define CRI_ASSERT_TYPE_TAG_i16       int16_t

#define CRI_ASSERT_TEST_TAG_i32       ,
#define CRI_ASSERT_TYPE_TAG_i32       int32_t

#define CRI_ASSERT_TEST_TAG_i64       ,
#define CRI_ASSERT_TYPE_TAG_i64       int64_t

#define CRI_ASSERT_TEST_TAG_u8        ,
#define CRI_ASSERT_TYPE_TAG_u8        uint8_t

#define CRI_ASSERT_TEST_TAG_u16       ,
#define CRI_ASSERT_TYPE_TAG_u16       uint16_t

#define CRI_ASSERT_TEST_TAG_u32       ,
#define CRI_ASSERT_TYPE_TAG_u32       uint32_t

#define CRI_ASSERT_TEST_TAG_u64       ,
#define CRI_ASSERT_TYPE_TAG_u64       uint64_t

#define CRI_ASSERT_TEST_TAG_int       ,
#define CRI_ASSERT_TYPE_TAG_int       int

#define CRI_ASSERT_TEST_TAG_uint      ,
#define CRI_ASSERT_TYPE_TAG_uint      unsigned int

#define CRI_ASSERT_TEST_TAG_long      ,
#define CRI_ASSERT_TYPE_TAG_long      long

#define CRI_ASSERT_TEST_TAG_ulong     ,
#define CRI_ASSERT_TYPE_TAG_ulong     unsigned long

#define CRI_ASSERT_TEST_TAG_llong     ,
#define CRI_ASSERT_TYPE_TAG_llong     long long

#define CRI_ASSERT_TEST_TAG_ullong    ,
#define CRI_ASSERT_TYPE_TAG_ullong    unsigned long long

#define CRI_ASSERT_TEST_TAG_ptr       ,
#define CRI_ASSERT_TYPE_TAG_ptr       void *

#define CRI_ASSERT_TEST_TAG_str       ,
#define CRI_ASSERT_TYPE_TAG_str       char *

#define CRI_ASSERT_TEST_TAG_wcs       ,
#define CRI_ASSERT_TYPE_TAG_wcs       wchar_t *

#define CRI_ASSERT_TEST_TAG_tcs       ,
#define CRI_ASSERT_TYPE_TAG_tcs       _TCHAR *

#define CRI_ASSERT_TEST_TAG_flt       ,
#define CRI_ASSERT_TYPE_TAG_flt       float

#define CRI_ASSERT_TEST_TAG_dbl       ,
#define CRI_ASSERT_TYPE_TAG_dbl       double

#define CRI_ASSERT_TEST_TAG_ldbl      ,
#define CRI_ASSERT_TYPE_TAG_ldbl      long double

#ifdef __cplusplus
# include <complex>

# define CRI_ASSERT_TEST_TAG_cx_flt     ,
# define CRI_ASSERT_TYPE_TAG_cx_flt     std::complex<float>

# define CRI_ASSERT_TEST_TAG_cx_dbl     ,
# define CRI_ASSERT_TYPE_TAG_cx_dbl     std::complex<double>

# define CRI_ASSERT_TEST_TAG_cx_ldbl    ,
# define CRI_ASSERT_TYPE_TAG_cx_ldbl    std::complex<long double>

#elif __STDC_VERSION__ == 199901L && !defined (__STDC_NO_COMPLEX__)
# include <complex.h>

# define CRI_ASSERT_TEST_TAG_cx_flt     ,
# define CRI_ASSERT_TYPE_TAG_cx_flt     _Complex float

# define CRI_ASSERT_TEST_TAG_cx_dbl     ,
# define CRI_ASSERT_TYPE_TAG_cx_dbl     _Complex double

# define CRI_ASSERT_TEST_TAG_cx_ldbl    ,
# define CRI_ASSERT_TYPE_TAG_cx_ldbl    _Complex long double

#endif

#define CRI_ASSERT_SPEC_OP_LEN(...)            \
    CR_EXPAND(CR_VA_TAIL_SELECT64(__VA_ARGS__, \
            3, 3, 3, 3,                        \
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3,      \
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3,      \
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3,      \
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3,      \
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3,      \
            3, 3, 3, 3, 3, 3, 3, 2, 2, 2))

#define CRI_BINOP(Op, Actual, Ref)    Actual Op Ref
#define CRI_BINOP_EQ(Actual, Ref)     CRI_BINOP(==, Actual, Ref)
#define CRI_BINOP_NE(Actual, Ref)     CRI_BINOP(!=, Actual, Ref)
#define CRI_BINOP_LE(Actual, Ref)     CRI_BINOP(<=, Actual, Ref)
#define CRI_BINOP_LT(Actual, Ref)     CRI_BINOP(<, Actual, Ref)
#define CRI_BINOP_GE(Actual, Ref)     CRI_BINOP(>=, Actual, Ref)
#define CRI_BINOP_GT(Actual, Ref)     CRI_BINOP(>, Actual, Ref)

#ifdef __cplusplus
# define CRI_BINOP_T_EQ(Tag, Actual, Ref)           CRI_BINOP_EQ(Actual, Ref)
# define CRI_BINOP_T_NE(Tag, Actual, Ref)           CRI_BINOP_NE(Actual, Ref)
# define CRI_BINOP_T_LE(Tag, Actual, Ref)           CRI_BINOP_LE(Actual, Ref)
# define CRI_BINOP_T_LT(Tag, Actual, Ref)           CRI_BINOP_LT(Actual, Ref)
# define CRI_BINOP_T_GE(Tag, Actual, Ref)           CRI_BINOP_GE(Actual, Ref)
# define CRI_BINOP_T_GT(Tag, Actual, Ref)           CRI_BINOP_GT(Actual, Ref)
#else
# define CRI_BINOP_EQ_TAG(Tag, Op, Actual, Ref)     (!(CRI_USER_TAG_ID(eq, Tag)(Actual, Ref))) Op 0
# define CRI_BINOP_CMP_TAG(Tag, Op, Actual, Ref)    CRI_USER_TAG_ID(cmp, Tag)(Actual, Ref) Op 0

# define CRI_BINOP_T_EQ(Tag, Actual, Ref)           CRI_BINOP_EQ_TAG(Tag, ==, Actual, Ref)
# define CRI_BINOP_T_NE(Tag, Actual, Ref)           CRI_BINOP_EQ_TAG(Tag, !=, Actual, Ref)
# define CRI_BINOP_T_LE(Tag, Actual, Ref)           CRI_BINOP_CMP_TAG(Tag, <=, Actual, Ref)
# define CRI_BINOP_T_LT(Tag, Actual, Ref)           CRI_BINOP_CMP_TAG(Tag, <, Actual, Ref)
# define CRI_BINOP_T_GE(Tag, Actual, Ref)           CRI_BINOP_CMP_TAG(Tag, >=, Actual, Ref)
# define CRI_BINOP_T_GT(Tag, Actual, Ref)           CRI_BINOP_CMP_TAG(Tag, >, Actual, Ref)
#endif

#ifdef __cplusplus

/* *INDENT-OFF* */
namespace criterion { namespace internal { namespace stream_char_conv {
/* *INDENT-ON* */

std::ostream &operator<<(std::ostream &s, int8_t i)
{
    s << signed (i);
    return s;
}

std::ostream &operator<<(std::ostream &s, uint8_t i)
{
    s << unsigned (i);
    return s;
}

std::ostream &operator<<(std::ostream &s, char c)
{
    s << c;
    return s;
}

/* *INDENT-OFF* */
}}}
/* *INDENT-ON* */

# include <type_traits>
# include <utility>
template <typename T> constexpr T && cri_val_escape(T && t) {
    return std::move(t);
}
template <typename T> constexpr T &cri_val_escape(T &t) { return t; }
# define CRI_VALUE_ESCAPE(T, X)              cri_val_escape<std::remove_reference<T>::type>(X)
# define CRI_USER_TOSTR(Tag, Var)                                     \
    [&Var]() -> char * {                                              \
        using namespace criterion::internal::stream_char_conv;        \
        std::stringstream sstr;                                       \
        sstr << (Var);                                                \
        const std::string str = sstr.str();                           \
        char *out = static_cast<char *>(std::malloc(str.size() + 1)); \
        std::copy(str.begin(), str.end(), out);                       \
        out[str.size()] = '\0';                                       \
        return out;                                                   \
    } ()
# define CRI_ASSERT_UNPRINTABLE(Tag, Var)    (void *) CRI_USER_TOSTR(Tag, Var)
#else
# define CRI_VALUE_ESCAPE(T, X)              X
# define CRI_USER_TOSTR(Tag, Var)            CRI_USER_TAG_ID(tostr, Tag)(&(Var))
# define CRI_ASSERT_UNPRINTABLE(Tag, Var)    (void *) "<unprintable>"
#endif

#define CRI_ASSERT_SPECIFIER_VALUE(Val)           \
    1; do {                                       \
        cri_cond_un = (Val);                      \
        cri_assert_node_init(&cri_tmpn);          \
        cri_tmpn.repr = CR_STR(Val);              \
        cri_tmpn.pass = cri_cond_un;              \
        cri_assert_node_add(cri_node, &cri_tmpn); \
    } while (0)

#define CRI_ASSERT_SPECIFIER_OP2(Op, Name, Lhs, Rhs)                         \
    1; do {                                                                  \
        __typeof__ (Lhs)cri_lhs = CRI_VALUE_ESCAPE(decltype (cri_lhs), Lhs); \
        __typeof__ (Rhs)cri_rhs = CRI_VALUE_ESCAPE(decltype (cri_rhs), Rhs); \
        cri_cond_un = Op (cri_lhs, cri_rhs);                                 \
        cri_assert_node_init(&cri_tmpn);                                     \
        cri_tmpn.rtype = CRI_ASSERT_RT_STRING;                               \
        cri_tmpn.repr = CR_STR(Name(Lhs, Rhs));                              \
        cri_tmpn.actual = CRI_ASSERT_UNPRINTABLE(Tag, cri_lhs);              \
        cri_tmpn.expected = CRI_ASSERT_UNPRINTABLE(Tag, cri_rhs);            \
        cri_tmpn.pass = cri_cond_un;                                         \
        cri_assert_node_add(cri_node, &cri_tmpn);                            \
    } while (0)

#define CRI_ASSERT_SPECIFIER_OP3(Op, Name, Tag, Lhs, Rhs)                             \
    1; do {                                                                           \
        CRI_ASSERT_TYPE_TAG(Tag) cri_lhs = CRI_VALUE_ESCAPE(decltype (cri_lhs), Lhs); \
        CRI_ASSERT_TYPE_TAG(Tag) cri_rhs = CRI_VALUE_ESCAPE(decltype (cri_rhs), Rhs); \
        cri_cond_un = Op (Tag, cri_lhs, cri_rhs);                                     \
        cri_assert_node_init(&cri_tmpn);                                              \
        cri_tmpn.rtype = CRI_ASSERT_RT_STRING;                                        \
        cri_tmpn.repr = CR_STR(Name(Tag, Lhs, Rhs));                                  \
        cri_tmpn.actual = (void *) CRI_USER_TOSTR(Tag, cri_lhs);                      \
        cri_tmpn.expected = (void *) CRI_USER_TOSTR(Tag, cri_rhs);                    \
        cri_tmpn.pass = cri_cond_un;                                                  \
        cri_assert_node_add(cri_node, &cri_tmpn);                                     \
    } while (0)

#define CRI_ASSERT_SPECIFIER_OP_HELPER(Op, N, ...)    CR_DEFER(CR_CONCAT)(CRI_ASSERT_SPECIFIER_ ## Op, N)(__VA_ARGS__)

#define CRI_ASSERT_TEST_SPECIFIER_eq(...)             ,
#define CRI_ASSERT_SPECIFIER_eq(...)                  CRI_ASSERT_SPECIFIER_OP_HELPER(eq, CRI_ASSERT_SPEC_OP_LEN(__VA_ARGS__), __VA_ARGS__)
#define CRI_ASSERT_SPECIFIER_eq2(Lhs, Rhs)            CRI_ASSERT_SPECIFIER_OP2(CRI_BINOP_EQ, eq, Lhs, Rhs)
#define CRI_ASSERT_SPECIFIER_eq3(Tag, Lhs, Rhs)       CRI_ASSERT_SPECIFIER_OP3(CRI_BINOP_T_EQ, eq, Tag, Lhs, Rhs)

#define CRI_ASSERT_TEST_SPECIFIER_ne(...)             ,
#define CRI_ASSERT_SPECIFIER_ne(...)                  CRI_ASSERT_SPECIFIER_OP_HELPER(ne, CRI_ASSERT_SPEC_OP_LEN(__VA_ARGS__), __VA_ARGS__)
#define CRI_ASSERT_SPECIFIER_ne2(Lhs, Rhs)            CRI_ASSERT_SPECIFIER_OP2(CRI_BINOP_NE, ne, Lhs, Rhs)
#define CRI_ASSERT_SPECIFIER_ne3(Tag, Lhs, Rhs)       CRI_ASSERT_SPECIFIER_OP3(CRI_BINOP_T_NE, ne, Tag, Lhs, Rhs)

#define CRI_ASSERT_TEST_SPECIFIER_le(...)             ,
#define CRI_ASSERT_SPECIFIER_le(...)                  CRI_ASSERT_SPECIFIER_OP_HELPER(le, CRI_ASSERT_SPEC_OP_LEN(__VA_ARGS__), __VA_ARGS__)
#define CRI_ASSERT_SPECIFIER_le2(Lhs, Rhs)            CRI_ASSERT_SPECIFIER_OP2(CRI_BINOP_LE, le, Lhs, Rhs)
#define CRI_ASSERT_SPECIFIER_le3(Tag, Lhs, Rhs)       CRI_ASSERT_SPECIFIER_OP3(CRI_BINOP_T_LE, le, Tag, Lhs, Rhs)

#define CRI_ASSERT_TEST_SPECIFIER_lt(...)             ,
#define CRI_ASSERT_SPECIFIER_lt(...)                  CRI_ASSERT_SPECIFIER_OP_HELPER(lt, CRI_ASSERT_SPEC_OP_LEN(__VA_ARGS__), __VA_ARGS__)
#define CRI_ASSERT_SPECIFIER_lt2(Lhs, Rhs)            CRI_ASSERT_SPECIFIER_OP2(CRI_BINOP_LT, lt, Lhs, Rhs)
#define CRI_ASSERT_SPECIFIER_lt3(Tag, Lhs, Rhs)       CRI_ASSERT_SPECIFIER_OP3(CRI_BINOP_T_LT, lt, Tag, Lhs, Rhs)

#define CRI_ASSERT_TEST_SPECIFIER_ge(...)             ,
#define CRI_ASSERT_SPECIFIER_ge(...)                  CRI_ASSERT_SPECIFIER_OP_HELPER(ge, CRI_ASSERT_SPEC_OP_LEN(__VA_ARGS__), __VA_ARGS__)
#define CRI_ASSERT_SPECIFIER_ge2(Lhs, Rhs)            CRI_ASSERT_SPECIFIER_OP2(CRI_BINOP_GE, ge, Lhs, Rhs)
#define CRI_ASSERT_SPECIFIER_ge3(Tag, Lhs, Rhs)       CRI_ASSERT_SPECIFIER_OP3(CRI_BINOP_T_GE, ge, Tag, Lhs, Rhs)

#define CRI_ASSERT_TEST_SPECIFIER_gt(...)             ,
#define CRI_ASSERT_SPECIFIER_gt(...)                  CRI_ASSERT_SPECIFIER_OP_HELPER(gt, CRI_ASSERT_SPEC_OP_LEN(__VA_ARGS__), __VA_ARGS__)
#define CRI_ASSERT_SPECIFIER_gt2(Lhs, Rhs)            CRI_ASSERT_SPECIFIER_OP2(CRI_BINOP_GT, gt, Lhs, Rhs)
#define CRI_ASSERT_SPECIFIER_gt3(Tag, Lhs, Rhs)       CRI_ASSERT_SPECIFIER_OP3(CRI_BINOP_T_GT, gt, Tag, Lhs, Rhs)

#define CRI_ASSERT_TEST_SPECIFIER_not(...)            ,
#define CRI_ASSERT_SPECIFIER_not(E)              \
    CRI_OBSTRUCT_N(CRI_SPECIFIER_INDIRECT)()(E); \
    cri_cond_un = !cri_cond_un;                  \
    cri_assert_node_negate(cri_node)

#define CRI_ASSERT_SPECIFIER_ALL_INDIRECT(Cond, E)    ; cri_cond_un = CRI_OBSTRUCT_N(CRI_SPECIFIER_INDIRECT)()(E); Cond = Cond && cri_cond_un
#define CRI_ASSERT_TEST_SPECIFIER_all(...)            ,
#define CRI_ASSERT_SPECIFIER_all(...)                                                                          \
    cri_cond_def; int *cri_pass_orig = cri_pass; cri_pass = &cri_cond_un; do {                                 \
        cri_assert_node_init(&cri_tmpn);                                                                       \
        struct cri_assert_node *cri_tmp = cri_assert_node_add(cri_node, &cri_tmpn);                            \
        struct cri_assert_node *cri_node = cri_tmp;                                                            \
        int cri_cond_def = 1, cri_cond_un;                                                                     \
        int cri_cond = cri_cond_def CRITERION_APPLY(CRI_ASSERT_SPECIFIER_ALL_INDIRECT, cri_cond, __VA_ARGS__); \
        cri_node->pass = cri_cond;                                                                             \
        *cri_pass = *cri_pass && cri_cond;                                                                     \
    } while (0); cri_pass = cri_pass_orig

#define CRI_ASSERT_SPECIFIER_NONE_INDIRECT(Cond, E)    ; cri_cond_un = CRI_OBSTRUCT_N(CRI_SPECIFIER_INDIRECT)()(E); Cond = Cond && !(cri_cond_un)
#define CRI_ASSERT_TEST_SPECIFIER_none(...)            ,
#define CRI_ASSERT_SPECIFIER_none(...)                                                                          \
    cri_cond_def; int *cri_pass_orig = cri_pass; cri_pass = &cri_cond_un; do {                                  \
        cri_assert_node_init(&cri_tmpn);                                                                        \
        struct cri_assert_node *cri_tmp = cri_assert_node_add(cri_node, &cri_tmpn);                             \
        struct cri_assert_node *cri_node = cri_tmp;                                                             \
        int cri_cond_def = 1, cri_cond_un;                                                                      \
        int cri_cond = cri_cond_def CRITERION_APPLY(CRI_ASSERT_SPECIFIER_NONE_INDIRECT, cri_cond, __VA_ARGS__); \
        cri_node->pass = cri_cond;                                                                              \
        *cri_pass = *cri_pass && cri_cond;                                                                      \
    } while (0); cri_pass = cri_pass_orig

#define CRI_ASSERT_SPECIFIER_ANY_INDIRECT(Cond, E)    ; Cond = Cond || CRI_OBSTRUCT_N(CRI_SPECIFIER_INDIRECT)()(E)
#define CRI_ASSERT_TEST_SPECIFIER_any(...)            ,
#define CRI_ASSERT_SPECIFIER_any(...)                                                                          \
    cri_cond_def; int *cri_pass_orig = cri_pass; cri_pass = &cri_cond_un; do {                                 \
        cri_assert_node_init(&cri_tmpn);                                                                       \
        struct cri_assert_node *cri_tmp = cri_assert_node_add(cri_node, &cri_tmpn);                            \
        struct cri_assert_node *cri_node = cri_tmp;                                                            \
        int cri_cond_def = 0;                                                                                  \
        int cri_cond = cri_cond_def CRITERION_APPLY(CRI_ASSERT_SPECIFIER_ANY_INDIRECT, cri_cond, __VA_ARGS__); \
        cri_node->pass = cri_cond;                                                                             \
        *cri_pass = *cri_pass && cri_cond;                                                                     \
    } while (0); cri_pass = cri_pass_orig

#define CRI_ASSERT_DECLARE_NATIVE_CMP_FN(Tag)                         \
    static inline int CRI_USER_TAG_ID(cmp, Tag)(                      \
        CRI_ASSERT_TYPE_TAG(Tag) actual,                              \
        CRI_ASSERT_TYPE_TAG(Tag) expected)                            \
    {                                                                 \
        return actual < expected ? -1 : (actual == expected ? 0 : 1); \
    }                                                                 \
    static inline int CRI_USER_TAG_ID(eq, Tag)(                       \
        CRI_ASSERT_TYPE_TAG(Tag) actual,                              \
        CRI_ASSERT_TYPE_TAG(Tag) expected)                            \
    {                                                                 \
        return actual == expected ? 1 : 0;                            \
    }

#define CRI_ASSERT_DECLARE_NATIVE_FN(Tag, Fmt)       \
    CRI_ASSERT_DECLARE_NATIVE_CMP_FN(Tag)            \
    static inline char *CRI_USER_TAG_ID(tostr, Tag)( \
        CRI_ASSERT_TYPE_TAG(Tag) * e)                \
    {                                                \
        char *str = NULL;                            \
        cr_asprintf(&str, "%" Fmt, *e);              \
        return str;                                  \
    }

CRI_ASSERT_DECLARE_NATIVE_FN(i8, PRId8)
CRI_ASSERT_DECLARE_NATIVE_FN(i16, PRId16)
CRI_ASSERT_DECLARE_NATIVE_FN(i32, PRId32)
CRI_ASSERT_DECLARE_NATIVE_FN(i64, PRId64)
CRI_ASSERT_DECLARE_NATIVE_FN(u8, PRIu8)
CRI_ASSERT_DECLARE_NATIVE_FN(u16, PRIu16)
CRI_ASSERT_DECLARE_NATIVE_FN(u32, PRIu32)
CRI_ASSERT_DECLARE_NATIVE_FN(u64, PRIu64)
CRI_ASSERT_DECLARE_NATIVE_FN(int, "d")
CRI_ASSERT_DECLARE_NATIVE_FN(uint, "u")
CRI_ASSERT_DECLARE_NATIVE_FN(long, "ld")
CRI_ASSERT_DECLARE_NATIVE_FN(ulong, "lu")
CRI_ASSERT_DECLARE_NATIVE_FN(llong, "lld")
CRI_ASSERT_DECLARE_NATIVE_FN(ullong, "llu")
CRI_ASSERT_DECLARE_NATIVE_FN(ptr, "p")
CRI_ASSERT_DECLARE_NATIVE_FN(str, "s")
CRI_ASSERT_DECLARE_NATIVE_FN(wcs, "ls")

#if defined (_WIN32)
# include <tchar.h>
# if defined (_UNICODE)
CRI_ASSERT_DECLARE_NATIVE_FN(tcs, "ls")
# else
CRI_ASSERT_DECLARE_NATIVE_FN(tcs, "s")
# endif
#endif

#ifdef __cplusplus

# define CRI_ASSERT_DECLARE_COMPLEX_FN(Tag, Fmt)                      \
    static inline int CRI_USER_TAG_ID(eq, Tag)(                       \
        CRI_ASSERT_TYPE_TAG(Tag) actual,                              \
        CRI_ASSERT_TYPE_TAG(Tag) expected)                            \
    {                                                                 \
        return actual == expected ? 1 : 0;                            \
    }                                                                 \
    static inline char *CRI_USER_TAG_ID(tostr, Tag)(                  \
        CRI_ASSERT_TYPE_TAG(Tag) * e)                                 \
    {                                                                 \
        char *str = NULL;                                             \
        cr_asprintf(&str, "%" Fmt " + i%" Fmt, e->real(), e->imag()); \
        return str;                                                   \
    }

CRI_ASSERT_DECLARE_COMPLEX_FN(cx_flt, "f")
CRI_ASSERT_DECLARE_COMPLEX_FN(cx_dbl, "f")
CRI_ASSERT_DECLARE_COMPLEX_FN(cx_ldbl, "Lf")

#elif __STDC_VERSION__ == 199901L && !defined (__STDC_NO_COMPLEX__)

# define CRI_ASSERT_DECLARE_COMPLEX_FN(Tag, Fmt, S)                             \
    static inline int CR_CONCAT(cr_user_eq_, CRI_ASSERT_TYPE_TAG_ID(Tag))(      \
        CRI_ASSERT_TYPE_TAG(Tag) actual,                                        \
        CRI_ASSERT_TYPE_TAG(Tag) expected)                                      \
    {                                                                           \
        return actual == expected ? 1 : 0;                                      \
    }                                                                           \
    static inline char *CR_CONCAT(cr_user_tostr_, CRI_ASSERT_TYPE_TAG_ID(Tag))( \
        CRI_ASSERT_TYPE_TAG(Tag) * e)                                           \
    {                                                                           \
        char *str = NULL;                                                       \
        cr_asprintf(&str, "%" Fmt " + i%" Fmt, creal ## S(*e), cimag ## S(*e)); \
        return str;                                                             \
    }

CRI_ASSERT_DECLARE_COMPLEX_FN(cx_flt, "f", f)
CRI_ASSERT_DECLARE_COMPLEX_FN(cx_dbl, "f", )
CRI_ASSERT_DECLARE_COMPLEX_FN(cx_ldbl, "Lf", l)
#endif

#undef cr_assert_user
#define cr_assert_user(File, Line, Fail, ...) \
    CRI_ASSERT_CALL(File, Line, Fail, CR_VA_HEAD(__VA_ARGS__), , CR_VA_TAIL(__VA_ARGS__))

#undef cr_assert_fail_user
#define cr_assert_fail_user(File, Line, Fail, ...)    CRI_ASSERT_FAIL(File, Line, Fail, , __VA_ARGS__)

#undef cr_assert
#define cr_assert(...)    cr_assert_user(__FILE__, __LINE__, criterion_abort_test, __VA_ARGS__)

#undef cr_expect
#define cr_expect(...)    cr_assert_user(__FILE__, __LINE__, criterion_continue_test, __VA_ARGS__)

#undef cr_assert_fail
#define cr_assert_fail(...)    cr_assert_fail_user(__FILE__, __LINE__, criterion_abort_test, __VA_ARGS__)

#undef cr_expect_fail
#define cr_expect_fail(...)    cr_assert_fail_user(__FILE__, __LINE__, criterion_continue_test, __VA_ARGS__)

#undef cr_skip
#define cr_skip(...)    criterion_skip_test("" __VA_ARGS__)

#endif /* !CRITERION_INTERNAL_NEW_ASSERTS_H_ */
