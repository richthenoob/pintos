#ifndef FIXED_POINT_ARITHMETIC_H
#define FIXED_POINT_ARITHMETIC_H
#include <stdint.h>

typedef int fixed_point_t;

/* The multiplicand(2 to the power of 14) when converting an integer into 17.14 fixed-point number representation.*/
#define FIXED_POINT_FORMAT_CONSTANT 16384

/* Convert n to fixed-point number representation.*/
#define CONVERT_TO_FIXED_POINT(n) ((n) * FIXED_POINT_FORMAT_CONSTANT)

/* Convert x to integer representation(rounding toward zero).*/
#define CONVERT_TO_INTEGER_TOWARDS_ZERO(x) ((x) / FIXED_POINT_FORMAT_CONSTANT)

/* Convert x to integer representation(rounding to nearest).*/
#define CONVERT_TO_INTEGER_TO_NEAREST(x) ((x) >= 0 ? (((x) + FIXED_POINT_FORMAT_CONSTANT / 2) / \
FIXED_POINT_FORMAT_CONSTANT) : (((x) - FIXED_POINT_FORMAT_CONSTANT / 2) / FIXED_POINT_FORMAT_CONSTANT))

/* Add two fixed-point numbers together.*/
#define ADD_TWO_FIXED_POINTS(x, y) ((x) + (y))

/* Add a fixed-point number x and an integer n together.*/
#define ADD_FIXED_POINT_AND_INTEGER(x, n) ((x) + (n) * FIXED_POINT_FORMAT_CONSTANT)

/* Subtract two fixed-point numbers.*/
#define SUBTRACT_TWO_FIXED_POINTS(x, y) ((x) - (y))

/* Subtract an integer n from a fixed-point number x.*/
#define SUBTRACT_INTEGER_FROM_FIXED_POINT(x, n) ((x) - (n) * FIXED_POINT_FORMAT_CONSTANT)

/* Multiply two fixed-point numbers.*/
#define MULTIPLY_TWO_FIXED_POINTS(x, y) (((int64_t) (x)) * (y) / FIXED_POINT_FORMAT_CONSTANT)

/* Multiply a fixed-point number x and an integer n.*/
#define MULTIPLY_FIXED_POINT_AND_INTEGER(x, n) ((x) * (n))

/* Divide two fixed-point numbers.*/
#define DIVIDE_TWO_FIXED_POINT(x, y) (((int64_t) (x)) * FIXED_POINT_FORMAT_CONSTANT / (y))

/* Divide a fixed-point number x by an integer n.*/
#define DIVIDE_FIXED_POINT_BY_INTEGER(x, n) ((x) / (n))

#endif /* threads/fixed_point_arithmetic.h */
