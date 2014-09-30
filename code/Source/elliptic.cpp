/*
Copyright (c) 2014
Milan Bohacek <milan.bohacek+bignum@gmail.com>
All rights reserved.

==============================================================================

This file is part of Bignum dumper.

Bignum dumper is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

==============================================================================
*/

#include <mpir.h>
#include <mpirxx.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <time.h>
#include "dumper.h"
#include <sstream>
#include "elliptic.h"

mpz_class InvertMod( const mpz_class & x, const mpz_class & mod )
{
	mpz_class z;
	int status = mpz_invert( z.get_mpz_t(), x.get_mpz_t(), mod.get_mpz_t() );
	if( status == 0 )
		return 0;
	return z;
}

//binary multiplication / power
ec_point_t elliptic_curve_t::times( mpz_class m, const ec_point_t r )
{
	if( m == 0 )
		return one();

	if( m == 1 )
		return ec_point_t( r );

	if( m < 0 )
	{

		ec_point_t i = inverse( r );
		return times( -m, i );
	}
	ec_point_t c = one();

	ec_point_t s = r;

	while( m > 0 )
	{
		if( (m & 1) == 1 )
		{
			c = plus( c, s );
		}
		s = plus( s, s );
		m = m >> 1;
	}
	return c;
}

//===================================================================================
//               https://hyperelliptic.org/EFD/g1p/auto-shortw.html
//===================================================================================

ec_point_t ShortWeierstrass::plus( const ec_point_t & P, const ec_point_t & Q )
{
	ec_point_t c;
	mpz_class s;


	if( !P.inf )
	{
		if( Q.inf )
			return P;

		if( (P.x % n) != (Q.x % n) )
		{
			mpz_class jmenovatel = (P.x - Q.x) % n;
			s = ((P.y - Q.y) * InvertMod( jmenovatel, n )) % n;
		}
		else if( (P.y % n) == (-Q.y % n) )
		{
			return one();
		}
		else
		{
			mpz_class jmenovatel = (2 * P.y) % n;
			s = ((3 * P.x * P.x + a) * InvertMod( jmenovatel, n )) % n;
		}
		mpz_class c1 = (-P.x - Q.x + s * s) % n;
		mpz_class c2 = (P.y + s * (c1 - P.x)) % n;
		c = ec_point_t{ c1, -c2, false };
		return c;
	}
	else
	{
		return Q;
	}
}

bool ShortWeierstrass::test( const ec_point_t & p )
{
	mpz_class LHS;
	mpz_class RHS;

	LHS = (p.y*p.y) % n;
	RHS = (((p.x*p.x*p.x) % n) + (a*p.x) % n + b) % n;
	return (RHS - LHS) % n == 0;
}

ec_point_t ShortWeierstrass::one()
{
	ec_point_t p = { 0, 0, true };
	return p;
}

ec_point_t ShortWeierstrass::inverse( const ec_point_t  & p1 )
{
	if( p1.inf )
		return p1;
	return ec_point_t( { p1.x, (-p1.y) % n, true } );
}


//===================================================================================
//               https://hyperelliptic.org/EFD/g1p/auto-twisted.html
//===================================================================================
//neutral point: (0,1)

ec_point_t TwistedEdwards::plus( const ec_point_t & P, const ec_point_t & Q )
{
	ec_point_t c;
	mpz_class s;

	s = (d*P.x*Q.x*P.y*Q.y) % n;

	mpz_class d1 = 1 + s;
	d1 = InvertMod( d1, n );
	mpz_class d2 = (1 - s);
	d2 = InvertMod( d2, n );

	mpz_class x3 = (((P.x*Q.y) % n + (P.y*Q.x) % n) *d1) % n;
	mpz_class y3 = (((P.y*Q.y) % n - (a*P.x*Q.x) % n) *d2) % n;

	return ec_point_t{ x3, y3, x3 == 0 && y3 == 1 };
}

bool TwistedEdwards::test( const ec_point_t & p )
{
	mpz_class LHS;
	mpz_class RHS;
	/*
	LHS = (a*p.x *p.x + p.y * p.y) % n;
	RHS = (1 + d*p.x *p.x * p.y *p.y) % n;
	*/

	LHS = (a*p.x *p.x + p.y * p.y) % n;
	RHS = (1 + d*p.x *p.x * p.y *p.y) % n;
	return (RHS - LHS) % n == 0;
}

ec_point_t TwistedEdwards::one()
{
	ec_point_t p = { 0, 1, true };
	return p;
}


ec_point_t TwistedEdwards::inverse( const ec_point_t  & p1 )
{
	if( p1.inf )
		return p1;
	return ec_point_t( { (-p1.x) % n, p1.y, p1.x == 0 && p1.y == 1 } );
}


//===================================================================================
//               https://hyperelliptic.org/EFD/g1p/auto-edwards.html
//===================================================================================
//neutral point: (0,c)

ec_point_t Edwards::plus( const ec_point_t & P, const ec_point_t & Q )
{
	mpz_class s;

	s = (d*P.x*Q.x*P.y*Q.y) % n;

	mpz_class d1 = (1 + s)*c;
	d1 = InvertMod( d1, n );
	mpz_class d2 = (1 - s)*c;
	d2 = InvertMod( d2, n );

	mpz_class x3 = (((P.x*Q.y) % n + (P.y*Q.x) % n) *d1) % n;
	mpz_class y3 = (((P.y*Q.y) % n - (P.x*Q.x) % n) *d2) % n;
	return ec_point_t{ x3, y3, x3 == 0 && y3 == c };
}

bool Edwards::test( const ec_point_t & p )
{
	mpz_class LHS;
	mpz_class RHS;
	LHS = (p.x *p.x + p.y * p.y) % n;
	RHS = (c *c * ((1 + d*p.x *p.x * p.y *p.y) % n)) % n;
	return (RHS - LHS) % n == 0;
}

ec_point_t Edwards::one()
{
	ec_point_t p = { 0, c, true };
	return p;
}


ec_point_t Edwards::inverse( const ec_point_t  & p1 )
{
	if( p1.inf )
		return p1;
	return ec_point_t( { (-p1.x) % n, p1.y, p1.x == 0 && p1.y == c } );
}
