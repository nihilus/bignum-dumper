#pragma once

#include <mpir.h>
#include <mpirxx.h>

class ec_point_t
{
public:
	mpz_class x;
	mpz_class y;
	bool inf;


	bool same( const ec_point_t & other )
	{
		if( inf )
		{
			if( other.inf )
			{
				return true;
			}
		}
		if( x != other.x )
			return false;
		if( y != other.y )
			return false;
		return true;
	}
	//todo:
	//mpz_class z;
};


class elliptic_curve_t
{
public:
	bool is_zero();
	virtual ec_point_t plus( const ec_point_t &, const ec_point_t & ) = 0;
	virtual ec_point_t one() = 0;
	virtual ec_point_t inverse( const ec_point_t  & ) = 0;
	virtual bool test( const ec_point_t  & ) = 0;
	virtual bool same( elliptic_curve_t * other ) = 0;
	virtual int get_id() = 0;

	ec_point_t elliptic_curve_t::times( mpz_class m, const ec_point_t r );

	
	
};

class ShortWeierstrass: public elliptic_curve_t
{
	typedef ShortWeierstrass self;
public:
	mpz_class a;
	mpz_class b;
	mpz_class n;

	virtual ec_point_t ShortWeierstrass::plus( const ec_point_t & P, const ec_point_t & Q );
	virtual bool ShortWeierstrass::test( const ec_point_t & p );
	virtual ec_point_t ShortWeierstrass::one();
	virtual ec_point_t ShortWeierstrass::inverse( const ec_point_t  & p1 );

	virtual int get_id()
	{
		return 0;
	}

	virtual bool same( elliptic_curve_t * other )
	{
		if( !other )
			return false;
		if( other->get_id() != get_id() )
		{
			return false;
		}

		self * Other = (self *)other;
		if( Other->a != a )
			return false;

		if( Other->b != b )
			return false;

		if( Other->n != n )
			return false;
		return true;
	}
	
};

class TwistedEdwards: public elliptic_curve_t
{
	typedef TwistedEdwards self;
public:
	mpz_class a;
	mpz_class d;
	mpz_class n;

	virtual ec_point_t TwistedEdwards::plus( const ec_point_t & P, const ec_point_t & Q );
	virtual bool TwistedEdwards::test( const ec_point_t & p );
	virtual ec_point_t TwistedEdwards::one();
	virtual ec_point_t TwistedEdwards::inverse( const ec_point_t  & p1 );

	virtual int get_id()
	{
		return 1;
	}

	virtual bool same( elliptic_curve_t * other )
	{
		if( !other )
			return false;
		if( other->get_id() != get_id() )
		{
			return false;
		}

		self * Other = (self *)other;
		if( Other->a != a )
			return false;

		if( Other->d != d )
			return false;

		if( Other->n != n )
			return false;
		return true;
	}
};


class Edwards: public elliptic_curve_t
{
	typedef Edwards self;
public:
	mpz_class c;
	mpz_class d;
	mpz_class n;

	virtual ec_point_t Edwards::plus( const ec_point_t & P, const ec_point_t & Q );
	virtual bool Edwards::test( const ec_point_t & p );
	virtual ec_point_t Edwards::one();
	virtual ec_point_t Edwards::inverse( const ec_point_t  & p1 );

	virtual int get_id()
	{
		return 2;
	}

	virtual bool same( elliptic_curve_t * other )
	{
		if( !other )
			return false;
		if( other->get_id() != get_id() )
		{
			return false;
		}

		self * Other = (self *)other;
		if( Other->c != c )
			return false;

		if( Other->d != d )
			return false;

		if( Other->n != n )
			return false;
		return true;
	}
};