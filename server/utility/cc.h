#ifndef CC_H
#define CC_H

#if defined(__clang__)
# if __clang_major__ >= 4
#  define JT_CC_MODERN 1
# endif
#elif defined(__GNUC__)
# if __GNUC__ >= 5
#  define JT_CC_MODERN 1
# endif
#endif

#ifndef __FRAMAC__
/* Do not warn if this function/variable/type is defined but never used. */
# define JT_CC_UNUSED __attribute__((__unused__))
/* Branch direction hint: `X` will probably happen. */
# define JT_CC_LIKELY(X) __builtin_expect(!!(X), 1)
/* Branch direction hint: `X` will probably not happen. */
# define JT_CC_UNLIKELY(X) __builtin_expect(!!(X), 0)
/* Export this symbol from the final shared object. */
# define JT_CC_PUBLIC __attribute__((visibility("default")))
/* Truly pure function (does not even read pointers/global memory). */
# define JT_CC_CONST __attribute__((__const__))
/* Side-effect free and deterministic function (i.e., safe for CSE). */
# define JT_CC_PURE __attribute__((__pure__))
/* Uses format strings like ARCHETYPE. */
# define JT_CC_FORMAT(ARCHETYPE, FORMAT_STRING_INDEX, FIRST_TO_CHECK)	\
	__attribute__((__format__(ARCHETYPE, FORMAT_STRING_INDEX, FIRST_TO_CHECK)))
/* This result is important; callers shouldn't discard it. */
# define JT_CC_WARN_UNUSED __attribute__((__warn_unused_result__))
/* Index of arguments that should never be NULL. */
# define JT_CC_NONNULL(...) __attribute__((__nonnull__(__VA_ARGS__)))

# ifdef JT_CC_MODERN
/* Return value is a chunk of memory of size (size) or (nmemb, size). */
#  define JT_CC_ALLOC_SIZE(...) __attribute__((__alloc_size__(__VA_ARGS__)))
/* Return value is non-NULL. */
#  define JT_CC_RETURNS_NONNULL __attribute__((__returns_nonnull__))
# else
#  define JT_CC_ALLOC_SIZE(...)
#  define JT_CC_RETURNS_NONNULL
# endif

/* This function never returns (e.g., abort()). */
#define JT_CC_NORETURN __attribute__((__noreturn__))
#else /* __FRAMAC__ */
# define JT_CC_UNUSED
# define JT_CC_LIKELY(X) (!!(X))
# define JT_CC_UNLIKELY(X) (!!(X))
# define JT_CC_PUBLIC
# define JT_CC_CONST
# define JT_CC_PURE
# define JT_CC_FORMAT(...)
# define JT_CC_WARN_UNUSED
# define JT_CC_NONNULL(...)
# define JT_CC_ALLOC_SIZE(...)
# define JT_CC_RETURNS_NONNULL
# define JT_CC_NORETURN
#endif

/*
 * BUILD_ASSERT, BUILD_ASSERT_OR_ZERO, _array_size_check were derived from
 * Rusty Russell's http://git.ozlabs.org/
 */

/* Compiler will fail if condition isn't true */
#define BUILD_ASSERT(cond)      \
        do { (void) sizeof(char [1 - 2*!(cond)]); } while(0)

/* Compiler will fail if condition isn't true */
#define BUILD_ASSERT_OR_ZERO(cond)      \
        (sizeof(char [1 - 2*!(cond)]) - 1)

/* 0 or fail to build */
#define _array_size_check(arr)  \
        BUILD_ASSERT_OR_ZERO(!__builtin_types_compatible_p(__typeof__(arr), \
                                __typeof__(&(arr)[0])))

#ifndef __FRAMAC__
#define JT_STATIC_ASSERT(CONDITION, DIAGNOSTIC)				\
	extern void							\
	lb_static_assert_proto(char static_assert_fail[static (CONDITION) ? 1 : -1], \
	    char [static 1 + 0 * sizeof(DIAGNOSTIC)])
#else
#define JT_STATIC_ASSERT(CONDITION, DIAGNOSTIC)
#endif

#ifndef __FRAMAC__
/* number of elements in array, with type checking */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + _array_size_check(arr))
#else
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif
#endif /*! CC_H */
