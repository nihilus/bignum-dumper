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
#include <vector>
#include <time.h>
#include "dumper.h"
#include <sstream>
#include "elliptic.h"

int counter = 0;

std::stringstream log_stream;


struct ec_curve_info_t
{
	elliptic_curve_t * curve;
	ec_point_t pt;
	int name;

	bool operator==(const ec_curve_info_t & other)
	{
		if( !curve )
			return false;
		if( !other.curve )
			return false;
		return other.curve->same( curve );
	}

	ec_curve_info_t( elliptic_curve_t * c, const ec_point_t & p )
	{
		pt = p;
		curve = c;
		name = counter++;
	}
};
typedef ec_curve_info_t * pec_curve_info_t;

#define Big mpz_class

void wiener( const Big & n, const Big & e );

//borrowed from RAT

mpir_ui bits( const mpz_class &n )
{
	return mpz_sizeinbase( n.get_mpz_t(), 2 );
}

mpir_ui len( const mpz_class &n )
{
	return mpz_size( n.get_mpz_t() );
}

bool prime( const mpz_class &n, mpir_ui tests )
{
	return mpz_probab_prime_p( n.get_mpz_t(), tests );
}

Big pow( const Big & base, const Big & exp, const Big &mod )
{
	Big result;
	mpz_powm( result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t() );
	return result;
}

Big pow( const Big &x, const mpir_ui e )
{
	Big result;
	mpz_pow_ui( result.get_mpz_t(), x.get_mpz_t(), e );
	return result;
}

Big pow( const Big &x, const  mpir_ui e, const Big & mod )
{
	Big result;
	mpz_powm_ui( result.get_mpz_t(), x.get_mpz_t(), e, mod.get_mpz_t() );
	return result;
}

Big inverse( const Big &val, const Big &modulo )
{
	Big result;
	mpz_invert( result.get_mpz_t(), val.get_mpz_t(), modulo.get_mpz_t() );
	return result;
}

Big gcd( const Big &a, const Big &b )
{
	Big result;
	mpz_gcd( result.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t() );
	return result;
}

Big modmult( const Big & A, const Big &x, const Big &n )
{
	return (A*x) % n;
}

bool isone( const Big & n )
{
	return n == 1;
}

bool iszero( const Big & n )
{
	return n == 0;
}


Big root( const Big & A, const mpir_ui & n )
{
	mpz_class result;
	mpz_nthroot( result.get_mpz_t(), A.get_mpz_t(), n );
	return result;
}

bool Wener_Attack( const Big & n, const Big & e )
{
	/* Small prime difference attack a.k.a Wener attack */

	Big x, y, p, q, d, u, v;


	{
		/* start of algo*/
		for( x = 2 * sqrt( n );; x += 1 )
		{
			u = pow( x, 2 ) - 4 * n;
			if( u > 1 )
			{
				v = sqrt( u );
				if( pow( v, 2 ) == u )
				{
					y = sqrt( pow( x, 2 ) - 4 * n );

					p = (x + y) / 2;
					q = (x - y) / 2;
					break;
				}
			}
		}

		/* end of algo*/

		/* print values */
		log_stream << "Wener attact factorisation is:" << std::endl;
		d = inverse( e, Big( (mpz_class)(p - 1)*(q - 1) ) );
		log_stream << "d:" << d << std::endl;
		log_stream << "p:" << p << std::endl;
		log_stream << "q:" << q << std::endl;
		return true;

	}
}


bool Wiener_Attack( const Big & n, const Big & e )
{
	/*
		Wiener Attack on RSA (small private exponent)
		works if  q < p < 2*q and d < 1/3*(n)^(1/4)
		*/

	Big d, p, q, pj, qj, pk, qk, ai, bi, aj, bj, pi, qi, l, crt, sum, dif;
	bool succes = false;

	/* start of algo : continue fraction method*/
	/* calculate l = 1/3*(n)^(1/4) */
	l = root( n, 4 ) / 3;
	/* initiliase: */
	crt = n;
	aj = 0;
	bj = e;
	ai = crt / bj;
	bi = crt%bj;
	crt = bj;

	pk = 0;
	qk = 1;
	pj = ai * aj + 1;
	qj = ai;

	for( ;; )
	{
		aj = crt / bi;
		bj = crt%bi;
		crt = bi;

		pi = aj * pj + pk;
		qi = aj * qj + qk;

		if( qi > l )
		{
			succes = false;
			break;
		}
		sum = n - (qi*e - 1) / pi + 1;
		mpz_class cc = (sum / 2)*(sum / 2) - n;
		if( cc < 0 )
			return false;
		dif = sqrt( cc ) * 2;
		p = (sum + dif) / 2;
		q = (sum - dif) / 2;
		if( p*q == n )
		{
			succes = true;
			break;
		}
		ai = bi;
		bi = bj;
		pk = pj;
		pj = pi;
		qk = qj;
		qj = qi;
	}

	/* end of algo*/
	if( succes )
	{
		/* print values */
		log_stream << "factorisation is:" << std::endl;
		d = inverse( e, (p - 1)*(q - 1) );
		log_stream << "d:" << d << std::endl;
		log_stream << "p:" << p << std::endl;
		log_stream << "q:" << q << std::endl;
	}

	return succes;
}



void elliptic_info( const Big & x, const Big & y, const Big & a, const Big & b, const Big  & n )
{
	log_stream << "short Weierstrass curve: " << counter - 1 << std::endl << "x: " << x << std::endl << "y: " << y << std::endl;
	log_stream << "a: " << a << std::endl;
	log_stream << "b: " << b << std::endl;
	log_stream << "p: " << n << std::endl << std::endl;

	Big delta = -16 * (4 * a*a*a + 27 * b*b);

	log_stream << "discriminant= " << delta << std::endl;
	if( delta == 0 )
	{
		log_stream << "curve is singular" << std::endl;
	}
	else
	{
		Big j = -1728 * (4 * a)*(4 * a)*(4 * a);
		Big g = gcd( j, delta );
		j /= g;
		delta /= g;
		if( delta < 0 )
		{
			j = -j; delta = -delta;
		}
		if( delta > 1 )
		{
			log_stream << "j-invariant = " << j << "/" << delta << std::endl;
		}
		else
		{
			log_stream << "j-invariant = " << j << std::endl;
		}
		if( j == 0 || j == 1728 )
		{
			log_stream << "Curve is anomalous." << std::endl;
		}
	}
}



bool Elliptic( const Big & x, const Big & y, const Big & A, const Big & B, const Big  & n, pec_curve_info_t &  pt )
{
	if( iszero( n ) ) return false;
	if( isone( n ) ) return false;
	if( n < 5 ) return false;
	if( n < A ) return false;
	if( n < B ) return false;
	if( n < x ) return false;
	if( n < y ) return false;

	ShortWeierstrass s;
	s.a = A;
	s.b = B;
	s.n = n;
	ec_point_t p = { x, y, false };

	if( s.test( p ) )
	{
		pt = new ec_curve_info_t( new ShortWeierstrass( s ), p );
		return true;
	}

	return false;
}

// source: https://hyperelliptic.org/EFD/

//Edwards curves : x^2 + y^2 = c^2*(1 + d*x^2*y^2)

bool Edwards( const Big & x, const Big & y, const Big & c, const Big & d, const Big  & n, pec_curve_info_t &pt )
{
	if( iszero( n ) ) return false;
	if( isone( n ) ) return false;
	if( x == -1 )
		return false;
	if( y == -1 )
		return false;

	if( n < 5 ) return false;

	if( n == y )
		return false;
	if( n == x )
		return false;
	if( n < x ) return false;
	if( n < y ) return false;

	Big LHS = (x *x + y * y) % n;
	Big RHS = (c *c * (1 + d*x *x * y *y)) % n;

	if( (LHS - RHS) % n == 0 ) return true;
	return false;
}

void Edwards_info( const Big & x, const Big & y, const Big & c, const Big & d, const Big  & n )
{
	log_stream << "Edwards curve: x^2 + y^2 = c^2*(1 + d*x^2*y^2)" << std::endl;
	log_stream << "x: " << x << std::endl << "y: " << y << std::endl;
	log_stream << "c: " << c << std::endl;
	log_stream << "d: " << d << std::endl;
	log_stream << "p: " << n << std::endl << std::endl;
}

bool twisted_Edwards( const Big & x, const Big & y, const Big & a, const Big & d, const Big  & n, pec_curve_info_t &pt )
{
	if( iszero( n ) ) return false;
	if( isone( n ) ) return false;
	if( n < 5 ) return false;

	if( x == 1 )
		return false;

	if( y == 1 )
		return false;

	if( n == y )
		return false;
	if( n == x )
		return false;

	if( n < x ) return false;
	if( n < y ) return false;

	TwistedEdwards s;
	s.a = a;
	s.d = d;
	s.n = n;
	ec_point_t p = { x, y, false };

	if( s.test( p ) )
	{
		pt = new ec_curve_info_t( new TwistedEdwards( s ), p );
		return true;
	}
	return false;
}

void twisted_Edwards_info( const Big & x, const Big & y, const Big & a, const Big & d, const Big  & n )
{
	log_stream << "twisted Edwards curve: a*x^2 + y^2 = 1 + d*x^2*y^2" << std::endl;
	log_stream << "x: " << x << std::endl << "y: " << y << std::endl;
	log_stream << "a: " << a << std::endl;
	log_stream << "d: " << d << std::endl;
	log_stream << "p: " << n << std::endl << std::endl;
}


typedef bool operace3( Big, Big, Big );
typedef bool operace4( Big, Big, Big, Big );
typedef bool operace5( Big, Big, Big, Big, Big );

template <typename T> struct funkce
{
	T *nazev;
	char *text;
};


bool Plus( Big a, Big b, Big c )
{
	if( (a + b) == c )
		return true;
	else
		return false;
}

bool Minus( Big a, Big b, Big c )
{
	if( (a - b) == c )
		return true;
	else
		return false;
}

bool Krat( Big a, Big b, Big c )
{
	if( (a * b) == c )
		return true;
	else
		return false;
}

bool Deleno( Big a, Big b, Big c )
{
	if( b == 0 ) return false;
	if( b == 1 ) return false;
	if( c == 1 ) return false;
	if( a < b )
		return false;

	if( (a / b) == c )
		return true;
	else
		return false;
}

bool Mod( Big a, Big b, Big c )
{
	if( b == 0 ) return false;
	if( b == 1 ) return false;
	if( a == c ) return false;
	if( (a % b) == c )
		return true;
	else
		return false;
}

bool Inverse( Big a, Big b, Big c )
{
	if( b == 0 ) return false;
	if( b == 1 ) return false;
	if( a == 1 ) return false;
	if( a == 0 ) return false;
	if( inverse( a, b ) == c )
		return true;
	else
		return false;
}

bool PowerMod( Big a, Big b, Big c, Big d )
{
	if( b == 0 ) return false;
	if( c == 0 ) return false;
	if( c == 1 ) return false;
	if( a == 0 ) return false;
	if( pow( a, b, c ) == d )
		return true;
	else
		return false;
}

bool PlusMod( Big a, Big b, Big c, Big d )
{
	if( c == 0 ) return false;
	if( c == 1 ) return false;
	if( (a + b) % c == d )
		return true;
	else
		return false;
}

bool MinusMod( Big a, Big b, Big c, Big d )
{
	if( c == 0 ) return false;
	if( c == 1 ) return false;
	if( (a - b) % c == d )
		return true;
	else
		return false;
}

bool DivMod( Big a, Big b, Big c, Big d )
{
	if( c == 0 ) return false;
	if( c == 1 ) return false;
	if( b == 0 ) return false;

	if( (a / b) % c == d )
		return true;
	else
		return false;
}

bool MulMod( Big a, Big b, Big c, Big d )
{
	if( c == 0 ) return false;
	if( c == 1 ) return false;
	if( (a*b) % c == d )
		return true;
	else
		return false;
}

bool Prime( Big n )
{
	if( prime( n, 8 ) )
		return true;
	else
		return false;
}


funkce<operace3> fce3[] = { { Plus, "+" }, { Minus, "-" }, { Krat, "*" }, { Deleno, "/" }, { Mod, "%" }, { Inverse, "^-1 mod " } };

funkce<operace4> fce4[] = {
		{ PlusMod, "(%s+%s) mod %s == %s\n" },
		{ MinusMod, "(%s-%s) mod %s == %s\n" },
		{ DivMod, "(%s/%s) mod %s == %s\n" },
		{ MulMod, "(%s*%s) mod %s == %s\n" },
		{ PowerMod, "pow(%s, %s, %s)==%s\n" }
};


bool powmod_test( const Big & x, const Big & e, const Big & n, const Big & y )
{
	if( iszero( e ) )
		return false;
	if( x > n )
		return false;
	if( y > n )
		return false;

	if( x == -1 )
		return false;

	if( e < 0 )
		return false;
	if( isone( x ) )
		return false;
	if( x == y )
		return false;

	return pow( x, e, n ) == y;
}



bool rsa_m_d_n( const Big & m, const Big & d, const Big & n )
{
	if( iszero( n ) )
		return false;
	if( iszero( d ) )
		return false;
	if( isone( d ) )
		return false;
	if( isone( n ) )
		return false;
	if( n < 0 )
		return false;
	if( d < 0 )
		return false;
	if( m < 2 )
		return false;
	if( n < m )
		return false;
	if( n < d )
		return false;

	Big p = pow( m, d, n );


	if( len( p ) < len( n ) - 2 )
	{
		log_stream << "possible decrypted rsa message:" << std::endl;
		log_stream << "m: " << m << std::endl;
		log_stream << "n: " << n << std::endl;
		log_stream << "d: " << d << std::endl;
		log_stream << "p: " << p << std::endl;

		std::string s;
		bool ok = true;
		while( p != 0 )
		{
			Big b = (p % 256);

			int ch = b.get_ui();
			if( ch > 127 )
			{
				ok = false;
				break;
			}
			s = (char)ch + s;
			p = p / 256;
		}
		if( ok )
			log_stream << "p2: " << s.c_str() << std::endl;

		return true;
	}
	else
	{
		return false;
	}
}

bool rsa_n_e_d( const Big & n, const Big & e, const Big & d )
{
	if( iszero( n ) )
		return false;
	if( iszero( e ) )
		return false;
	if( isone( n ) )
		return false;
	if( isone( e ) )
		return false;
	if( iszero( d ) )
		return false;
	if( n < e )
		return false;
	if( n < d )
		return false;
	if( e < 0 )
		return false;
	if( d < 0 )
		return false;
	//tady to trochu kulhá, ale e je skoro vždycky 65537, takže pravdìpodobnost, že by d<e je hodnì malá
	//ale stejne se zkouší všechny možnosti, takže je to jedno
	if( e > d )
		return false;
	if( (pow( pow( e, e, n ), d, n ) == e) && (pow( pow( d, e, n ), d, n ) == d) )
		//if ((pow(pow(17, e, n), d, n) == 17))
	{
		return true;
	}
	else
	{
		return false;
	}
}

//faktorizuje n, pokud máme e a d
bool rsa_n_e_d_factor( const Big & n, const Big & e, const Big & d )
{
	Big u = (e*d - 1);
	int c = 0;

	log_stream << "e*d-1: " << u << std::endl;

	if( u == 0 )
		return false;

	while( u % 2 == 0 )
	{
		u /= 2;
		c++;
	}

	
	gmp_randstate_t state = { 0 };
	gmp_randinit_default( state );
	gmp_randseed_ui( state, time( NULL ) );

	Big z;
	mpz_urandomm( z.get_mpz_t(), state, n.get_mpz_t() );


	Big z2;
	Big delitel;
	int counter;
	do
	{
		mpz_class R;
		mpz_urandomm( R.get_mpz_t(), state, n.get_mpz_t() );
		z = pow( R, u, n );
		z2 = pow( z, 2, n );
		counter = 0;
		while( z2 != 1 )
		{

			z = z2;
			z2 = pow( z, 2, n );
			if( counter++ > c )
			{
				log_stream << "neco je spatne v rsa_n_e_d_factor" << std::endl;
				log_stream << "counter: " << counter << std::endl;
				return false;
			}

		}
		//cout << "counter: " << counter <<std::endl;
		delitel = gcd( z - 1, n );
	} while( delitel == 1 || delitel == n );
	log_stream << n << " = " << delitel << " * " << n / delitel << std::endl << std::endl;
	return true;
}

void rsa_n_e_d_info( const Big & n, const Big & e, const Big & d )
{
	log_stream << "rsa magic numbers:" << std::endl;
	log_stream << "n: " << n << std::endl;
	log_stream << "e: " << e << std::endl;
	log_stream << "d: " << d << std::endl << std::endl;
	wiener( n, d );
}

void wiener( const Big & n, const Big & e )
{
	//Given p>0 and q>1
	/*
	b-2=p		x-2=0		y-2=1
	b-1=q		x-1=1		y-1=0
	Now for i=0,1,..... and for bi-1>0, find the quotient ai and remainder bi when bi-2 is divided by bi-1, such that
	bi = -ai.bi-1 + bi-2
	Then calculate
	xi = ai.xi-1 + xi-2
	yi = ai.yi-1 + yi-2
	*/

	// Algorithm from Wikipedia, Continued Fractions:
	Big hi = e;
	Big lo = n;



	Big n0 = 0;
	Big d0 = 1;


	Big n1 = 1;
	Big d1 = 0;
	Big fp = 0;

#define prt(x) cout << #x ":" << x <<std::endl;  
#define MAXWIENER 5000
	int c = MAXWIENER;
	while( c-- > 0 )
	{
		if( iszero( lo ) )
			goto end;
		Big a = hi / lo;
		Big f = hi % lo;
		Big n2 = n0 + n1*a;
		Big d2 = d0 + d1*a;
		n0 = n1;
		n1 = n2;
		d0 = d1;
		d1 = d2;
		fp = f;
		hi = lo;
		lo = f;
		if( n2 > 0 )
		{

			Big k = n2;
			Big d = d2;
			//prt(k);
			//prt(d);
			Big rem = (e*d - 1) % k;
			//prt(rem);
			if( iszero( rem ) && (!iszero( k )) )
			{
				Big fin = (e*d - 1) / k;
				/*
				{
				{x -> 1/2 (1 - fin - Sqrt[(-1 + fin - n)^2 - 4 n] + n)},
				{x ->  1/2 (1 - fin + Sqrt[(-1 + fin - n)^2 - 4 n] + n)}
				}

				List(List(Rule(x,(1 - fin - Sqrt(Power(-1 + fin - n,2) - 4*n) + n)/2.)),List(Rule(x,(1 - fin + Sqrt(Power(-1 + fin - n,2) - 4*n) + n)/2.)))
				*/
				Big tmp = -1 + fin - n;
				Big dis = (tmp*tmp) - 4 * n;
				if( dis >= 0 )
				{
					Big sqr = sqrt( dis );

					if( sqr * sqr == dis )
					{
						log_stream << "Wiener attack with " << std::endl;
						log_stream << "n:" << n << std::endl;
						log_stream << "e:" << e << std::endl;

						log_stream << "factorisation is:" << std::endl;
						log_stream << "c:" << MAXWIENER - c << std::endl;
						log_stream << "d:" << d << std::endl;
						log_stream << "p:" << (1 - fin - sqr + n) / 2 << std::endl;
						log_stream << "q:" << (1 - fin + sqr + n) / 2 << std::endl;
						return;
					}
				}
			}


		}
	}
end:
	//log_stream << "...failed." << std::endl;

	;
}

typedef std::vector<Big *> big_vector_t;
typedef std::vector<ec_curve_info_t *> point_vector_t;

typedef std::vector<bool> bool_vector_t;

int mensi( const Big * a, const Big * b )
{
	if( (*a) < (*b) )
	{
		return -1;
	}
	else
	{
		if( (*a) == (*b) )
		{
			return 0;
		}
		else
		{
			return 1;
		}
	}
}

#define MAX_NUMBERS 100

std::string guess_relations( number_list_t & numbers )
{
	ec_curve_info_t * body[ MAX_NUMBERS ];
	unsigned int body_size = 0;
	//bool_vector_t pouzite;
	Big cisla[ MAX_NUMBERS ] = { 0 };
	unsigned int cisla_size = 0;
	bool pouzite[ MAX_NUMBERS ] = { 0 };

	log_stream.str( std::string() );

	if( numbers.size() > 20 )
		return "too many numbers";

	std::copy( numbers.begin(), numbers.end(), cisla );

	cisla_size = numbers.size();

#define prnt(x) cout << #x ": " << (x) <<std::endl;


#define smycka(iter) for (unsigned int iter=0; iter<cisla_size; iter++)
#define smycka2(iter) for (unsigned int iter=0; iter<body_size; iter++)
#define prespole(pole, iter) for(int iter=0; iter < arraysz(pole); iter++)

#pragma omp parallel sections
	{
#pragma omp section 
		if( cisla_size >= 3 ) //mame dost cisel na 3 argumenty
		{
			smycka( j )
			{
				smycka( k )
				{
					if( j == k ) continue;
					smycka( l )
					{
						if( l == j ) continue;
						if( l == k ) continue;
						if( rsa_m_d_n( cisla[ j ], cisla[ k ], cisla[ l ] ) )
						{

						}
						if( rsa_n_e_d( cisla[ j ], cisla[ k ], cisla[ l ] ) )
						{
							rsa_n_e_d_info( cisla[ j ], cisla[ k ], cisla[ l ] );
							rsa_n_e_d_factor( cisla[ j ], cisla[ k ], cisla[ l ] );
						}

						prespole( fce3, i )
						{
							if( (fce3[ i ].nazev)(cisla[ j ], cisla[ k ], cisla[ l ]) )
							{
								log_stream << cisla[ j ] << " " << fce3[ i ].text << " " << cisla[ k ] << " == " << cisla[ l ] << std::endl;
							}
						}
					}
				}
				if( wasbreak() )
				{
					goto end;
				}
			}
		}
#pragma omp section 
		if( cisla_size >= 4 )
		{
			smycka( j )
			{
				smycka( k )
				{
					if( j == k ) continue;
					smycka( l )
					{
						if( l == j ) continue;
						if( l == k ) continue;
						smycka( m )
						{
							if( m == j ) continue;
							if( m == k ) continue;
							if( m == l ) continue;
							if( powmod_test( cisla[ j ], cisla[ k ], cisla[ l ], cisla[ m ] ) )
							{
								log_stream << "x^e mod n == y where" << std::endl;
								log_stream << "x: " << cisla[ j ] << std::endl;
								log_stream << "e: " << cisla[ k ] << std::endl;
								log_stream << "n: " << cisla[ l ] << std::endl;
								log_stream << "y: " << cisla[ m ] << std::endl;
								wiener( cisla[ l ], cisla[ k ] );
								Wiener_Attack( cisla[ l ], cisla[ k ] );
								//Wener_Attack(cisla[l], cisla[k]);
							}
						}
					}
				}
				if( wasbreak() )
				{
					goto end;
				}
			}
		}
#pragma omp section 
		if( cisla_size >= 5 )//mame dost cisel na 5 argumentu
		{
			smycka( j )
			{
				smycka( k )
				{
					if( j == k ) continue;
					smycka( l )
					{
						if( l == j ) continue;
						if( l == k ) continue;
						smycka( m )
						{
							if( m == j ) continue;
							if( m == k ) continue;
							if( m == l ) continue;
							smycka( n )
							{
								if( n == j ) continue;

								if( n == k ) continue;

								if( n == l ) continue;

								if( n == m ) continue;

								if( pouzite[ j ] )
									continue;

								if( pouzite[ k ] )
									continue;

								pec_curve_info_t newb = 0;

								if( Elliptic( cisla[ j ], cisla[ k ], cisla[ l ], cisla[ m ], cisla[ n ], newb ) )
								{
									pouzite[ j ] = true;
									pouzite[ k ] = true;
									pouzite[ l ] = true;
									pouzite[ m ] = true;
									pouzite[ n ] = true;

									//ecurve( cisla[ l ], cisla[ m ], cisla[ n ], MR_BEST );

									body[ body_size++ ] = newb;

									elliptic_info( cisla[ j ], cisla[ k ], cisla[ l ], cisla[ m ], cisla[ n ] );
									newb = 0;
								}
								if( Edwards( cisla[ j ], cisla[ k ], cisla[ l ], cisla[ m ], cisla[ n ], newb ) )
								{
									pouzite[ j ] = true;
									pouzite[ k ] = true;
									pouzite[ l ] = true;
									pouzite[ m ] = true;
									pouzite[ n ] = true;
									Edwards_info( cisla[ j ], cisla[ k ], cisla[ l ], cisla[ m ], cisla[ n ] );
								}

								if( twisted_Edwards( cisla[ j ], cisla[ k ], cisla[ l ], cisla[ m ], cisla[ n ], newb ) )
								{
									pouzite[ j ] = true;
									pouzite[ k ] = true;
									pouzite[ l ] = true;
									pouzite[ m ] = true;
									pouzite[ n ] = true;
									body[ body_size++ ] = newb;
									twisted_Edwards_info( cisla[ j ], cisla[ k ], cisla[ l ], cisla[ m ], cisla[ n ] );
								}

							}
						}
					}
					if( wasbreak() )
					{
						goto end;
					}
				}
			}
		}
	}

	log_stream << "==================" << std::endl;
	smycka2( j )
	{
		smycka2( k )
		{
			if( j == k )
				continue;
			smycka( i )
			{
				if( pouzite[ i ] )
					continue;

				if( (*body[ j ]) == (*body[ k ]) )//same curve
				{
					//body[ j ]->set();
					//cout << "pt[j]:" << body[j]->pt<<endl;
					//cout << "pt[k]:" << body[k]->pt<<endl;


					ec_point_t tmp = body[ j ]->curve->times( cisla[ i ], body[ j ]->pt );


					if( (tmp.same( body[ k ]->pt )) )
					{
						log_stream << cisla[ i ] << " * [" << body[ j ]->name << "] == [" << body[ k ]->name << "]" << std::endl;
					}
				}
			}
		}

		smycka( i )
		{
			if( pouzite[ i ] )
				continue;


			if( iszero( cisla[ i ] ) )
				continue;



			ec_point_t tmp = body[ j ]->curve->times( cisla[ i ], body[ j ]->pt );

			if( tmp.inf )
			{
				log_stream << cisla[ i ] << " * [" << body[ j ]->name << "] == [inf]" << std::endl;
			}
		}
	}
	log_stream << "==================" << std::endl;
	smycka( i )
	{
		if( prime( cisla[ i ], 8 ) )
		{
			log_stream << cisla[ i ] << " is prime (" << bits( cisla[ i ] ) << " bits)." << std::endl;
		}
	}


end:
	std::string str;
	str = log_stream.str();

	smycka2( j )
	{
		delete body[ j ];
	}
	return str;
}