/* A Bison parser, made by GNU Bison 3.5.1.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2020 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Undocumented macros, especially those whose name start with YY_,
   are private implementation details.  Do not rely on them.  */

#ifndef YY_PRSA_PRSA_PAR_H_INCLUDED
# define YY_PRSA_PRSA_PAR_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int prsadebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    COLON = 258,
    HEX = 259,
    OBRACE = 260,
    EBRACE = 261,
    TAG_RSA = 262,
    TAG_PUB = 263,
    TAG_PSK = 264,
    MODULUS = 265,
    PUBLIC_EXPONENT = 266,
    PRIVATE_EXPONENT = 267,
    PRIME1 = 268,
    PRIME2 = 269,
    EXPONENT1 = 270,
    EXPONENT2 = 271,
    COEFFICIENT = 272,
    ADDR4 = 273,
    ADDR6 = 274,
    ADDRANY = 275,
    SLASH = 276,
    NUMBER = 277,
    BASE64 = 278
  };
#endif
/* Tokens.  */
#define COLON 258
#define HEX 259
#define OBRACE 260
#define EBRACE 261
#define TAG_RSA 262
#define TAG_PUB 263
#define TAG_PSK 264
#define MODULUS 265
#define PUBLIC_EXPONENT 266
#define PRIVATE_EXPONENT 267
#define PRIME1 268
#define PRIME2 269
#define EXPONENT1 270
#define EXPONENT2 271
#define COEFFICIENT 272
#define ADDR4 273
#define ADDR6 274
#define ADDRANY 275
#define SLASH 276
#define NUMBER 277
#define BASE64 278

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 130 "prsa_par.y"

	BIGNUM *bn;
	RSA *rsa;
	char *chr;
	long num;
	struct netaddr *naddr;

#line 111 "prsa_par.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE prsalval;

int prsaparse (void);

#endif /* !YY_PRSA_PRSA_PAR_H_INCLUDED  */
