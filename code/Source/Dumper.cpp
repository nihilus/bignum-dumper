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

//TODO: get_user_idadir and custom settings

#include <mpir.h>
#include <mpirxx.h>
#include <memory>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#include <vector>
#include <string>
#include <sstream>
#include "dumper.h"
#include <expr.hpp>
#include <diskio.hpp>
#include "sdk_hacks.h"

#define VERSION "1.1"

number_list_t number_list;

qstrvec_t presets;
qstrvec_t word_size;
qstrvec_t endian;
qstrvec_t basis;

static form_actions_t *g_fa;

//enum COMMANDS
//{
#define	ID_ADDRESS 1
#define	ID_WORDS 2
#define	ID_WORD_SIZE 3
#define	ID_WORD_ENDIAN 4
#define	ID_BIGNUM_ENDIAN 5
#define	ID_DUMP 6
#define	ID_BIGNUM_LIST 7
#define	ID_GUESS 8
#define	ID_PRESET 9
#define	ID_BASE 10
#define	ID_SAVE 11
#define	ID_LOAD 12
#define	ID_GEN_IDC 13
#define	ID_REFRESH 14
#define	ID_GUESS_TYPE 15
#define	ID_EXAMPLE 16
//}


struct settings_t
{
	int word_size;
	int word_endian;
	int bignum_endian;
	char length_text[ MAXSTR ];
	char address_text[ MAXSTR ];
	int base_idx;
	uval_t length;
	ea_t address;

	//methods:

	qstring make_basexx_example();
	qstring make_example();

	int word_size_idx();
	int word_endian_idx();
	int bignum_endian_idx();
	size_t size()const;
	bool read_settings( form_actions_t &fa );
	bool dump( mpz_class &number );
};

void unregister_idc_functions();
void register_idc_functions();

asize_t get_BER_int_offset( ea_t ea );
asize_t get_BER_int_len( ea_t ea );

typedef char reverse_table[ 256 ];

bool set_preset( form_actions_t &fa, settings_t & settings );

//to add alphabet add string to alphabets[], push its name to basis qstrvec and optionally add its template and preset
char * alphabets[] = { "01", "01234567", "0123456789", "0123456789ABCDEF", "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };

const int nalphabets = arraysz( alphabets );
size_t alphabets_lengths[ nalphabets ];

reverse_table reverse[ nalphabets ];


void update_table( const char * alphabet, reverse_table & table )
{
	const size_t len = strlen( alphabet );
	for( size_t j = 0; j < len; ++j )
	{
		table[ alphabet[ j ] ] = j;
	}
}

void init_tables()
{
	for( size_t i = 0; i < nalphabets; ++i )
	{
		reverse_table & table = reverse[ i ];
		memset( &table, -1, sizeof( table ) );
		const char * alphabet = alphabets[ i ];

		update_table( alphabet, table );
		alphabets_lengths[ i ] = strlen( alphabet );
		//special ugly case for lowercase hex
		if( i == 3 )
		{
			update_table( "0123456789abcdef", table );
		}
	}
}


bool inited = false;

void initme()
{
	if( inited )
		return;
	init_tables();
	word_size.push_back( "1" );
	word_size.push_back( "2" );
	word_size.push_back( "4" );
	word_size.push_back( "8" );

	basis.push_back( "<raw>" );
	basis.push_back( "ascii 0/1" );
	basis.push_back( "octal" );
	basis.push_back( "decimal" );
	basis.push_back( "hexadecimal" );
	basis.push_back( "bitcoin base58" );
	basis.push_back( "base64" );

	presets.push_back( "<none>" );
	presets.push_back( "gmp 32bit" );
	presets.push_back( "BER encoded integer" );
	presets.push_back( "binary string" );
	presets.push_back( "octal string" );
	presets.push_back( "decimal string" );
	presets.push_back( "hexadecimal string" );
	presets.push_back( "bitcoin base58 string" );
	presets.push_back( "base64 string" );


	endian.push_back( "LSB" );
	endian.push_back( "MSB" );

	inited = true;
}


// word size, word endian, bignum_endian, length_text, address_text, base_idx
settings_t mpir_32_template = { 4, -1, -1, "Dword(here+4)", "Dword(here+8)", 0, 0, 0 };
settings_t mpir_BER_template = { 1, 1, 1, "BER_int_length(here)", "BER_int_offset(here)", 0, 0, 0 };
settings_t base_2_template = { 1, 1, 1, "ItemSize(here)", "here", 1, 0, 0 };
settings_t base_8_template = { 1, 1, 1, "ItemSize(here)", "here", 2, 0, 0 };
settings_t base_10_template = { 1, 1, 1, "ItemSize(here)", "here", 3, 0, 0 };
settings_t base_16_template = { 1, 1, 1, "ItemSize(here)", "here", 4, 0, 0 };
settings_t base_58_template = { 1, 1, 1, "ItemSize(here)", "here", 5, 0, 0 };
settings_t base_64_template = { 1, 1, 1, "ItemSize(here)", "here", 6, 0, 0 };

settings_t * templates[] = { &mpir_32_template, &mpir_BER_template, &base_2_template, &base_8_template, &base_10_template, &base_16_template, &base_58_template, &base_64_template };


void tobig( void * c, mpz_class & b )
{
	mpz_import( b.get_mpz_t(), 32, 1, sizeof( char ), 1, 0, c );
}

// the editor form
static TForm *editor_tform;

// chooser (list view) items
static const char *const names[] =
{
	"Item one",
	"Item two",
	"Item three"
};

// contents of the text field for each item
static qstring txts[] =
{
	"Text one:\n This is text for item one",
	"Text two:\n And this is text for item two",
	"Text three:\n And finally text for the last item"
};

// Current index for chooser list view
static int curidx = 0;
// Form actions for control dialog
static form_actions_t *control_fa;
// Defines where to place new/existing editor window
static bool dock = false;

// Form actions for editor window
enum editor_form_actions
{
	TEXT_CHANGED = 1,
	ITEM_SELECTED = 2,
};

// Form actions for control window
enum control_form_actions
{
	BTN_DOCK = 10,
	BTN_UNDOCK = 11,
	BTN_OPEN = 12,
	BTN_CLOSE = 13,
};

//--------------------------------------------------------------------------
// this callback is called when the user clicks on a button
static int idaapi btn_cb( TView *[], int )
{
	msg( "button has been pressed -> " );
	return 0;
}

void push_number( const mpz_class & number, bool update = true )
{
	number_list.push_back( number );

	if( update && g_fa )
		g_fa->refresh_field( ID_BIGNUM_LIST );
}

static bool evalidc( char *ch, ea_t &adr, ea_t ea = get_screen_ea() )
{
	char wstr[ MAXSTR ] = { 0 };
	idc_value_t v;
	bool b = calc_idc_expr( ea, ch, &v, wstr, MAXSTR );
	if( !b )
	{
		warning( wstr );
		return false;
	}
	if( !v.is_integral() )
		return false;
	switch( v.vtype )
	{
		case VT_LONG:
			adr = v.num;
			break;
		case VT_INT64:
			adr = v.i64;
			break;
		default:
			return false;
	}
	return true;
}


qstring settings_t::make_basexx_example()
{
	if( base_idx <= 0 )
		return "error";
	int idx = base_idx - 1;
	char * alphabet = alphabets[ idx ];
	char zero = alphabet[ 0 ];
	char one = alphabet[ 1 ];
	qstring s = "1 = [";

	const uval_t len = std::min( length, 31ull );
	const bool shortened = len != length;

	for( uval_t i = 0; i < len; ++i )
	{

		if( (i == 0 && bignum_endian == -1) || (i == len - 1 && bignum_endian == 1) )
		{
			s += one;
		}
		else
		{
			if( shortened && i == len / 2 )
			{
				s += "...";
			}
			else
				s += zero;
		}
	}
	s += "]";
	return s;
}

qstring settings_t::make_example()
{
	qstring word;
	qstring word1;
	uval_t max;

	if( base_idx != 0 )
	{
		return make_basexx_example();
	}

	switch( word_size )
	{
		case 1:
			word = "00";
			max = 15;
			break;
		case 2:;
			word = "00 00";
			max = 9;
			break;
		case 4:;
			word = "00 00 00 00";
			max = 7;
			break;
		case 8:;
			max = 3;
			word = "00 00 00 00 00 00 00 00";
			break;
		default:
			return "error";
	}
	word1 = word;
	switch( word_endian )
	{
		case 1:
			word1[ word1.length() - 1 ] = '1';
			break;
		case -1:
			word1[ 1 ] = '1';
			break;
		default:
			return "error in word endian";
			break;
	}

	switch( bignum_endian )
	{
		case 1:
			break;
		case -1:

			break;
		default:
			return "error in bignum endian";
			break;
	}

	qstring s = "1 = [";

	const uval_t len = std::min( length, max );
	const bool shortened = len != length;

	for( uval_t i = 0; i < len; ++i )
	{

		if( (i == 0 && bignum_endian == -1) || (i == len - 1 && bignum_endian == 1) )
		{
			s += word1;
		}
		else
		{
			if( shortened && i == len / 2 )
			{
				s += "...";
			}
			else
				s += word;
		}
		if( i != len - 1 )
		{
			s += "|";
		}
	}

	s += "]";
	return s;
}


int settings_t::word_size_idx()
{
	switch( word_size )
	{
		case 1:
			return 0;
			break;
		case 2:
			return 1;
			break;
		case 4:
			return 2;
			break;
		case 8:
			return 3;
			break;
		default:
			return 0;
	}
}

int settings_t::word_endian_idx()
{
	switch( word_endian )
	{
		case -1:
			return 0;
			break;
		case 1:
			return 1;
			break;
		default:
			return 0;
	}

}

int settings_t::bignum_endian_idx()
{
	switch( bignum_endian )
	{
		case -1:
			return 0;
			break;
		case 1:
			return 1;
			break;
		default:
			return 0;
	}
}

size_t settings_t::size()const
{
	return length * word_size;
}

bool settings_t::read_settings( form_actions_t &fa )
{
	if( !fa.get_ascii_value( ID_ADDRESS, address_text, MAXSTR ) )
		return false;

	if( !evalidc( address_text, address ) )
		return false;

	if( !fa.get_ascii_value( ID_WORDS, length_text, MAXSTR ) )
		return false;

	if( !evalidc( length_text, length, address ) )
		return false;

	if( !fa.get_combobox_value( ID_WORD_SIZE, &word_size ) )
		return false;
	if( !fa.get_combobox_value( ID_WORD_ENDIAN, &word_endian ) )
		return false;
	if( !fa.get_combobox_value( ID_BIGNUM_ENDIAN, &bignum_endian ) )
		return false;

	if( !fa.get_combobox_value( ID_BASE, &base_idx ) )
		return false;


	word_size = 1 << word_size;
	word_endian = word_endian == 1 ? 1 : -1;
	bignum_endian = bignum_endian == 1 ? 1 : -1;
	return true;
}

bool guess_template( form_actions_t &fa )
{
	char address_text[ MAXSTR ];
	ea_t address;

	if( !fa.get_ascii_value( ID_ADDRESS, address_text, MAXSTR ) )
		return false;

	if( !evalidc( address_text, address ) )
		return false;

	size_t to_probe = get_item_size( address );
	if( !isEnabled( address ) )
		return false;
	//check for gmp 32 bit bignum
	{
		uval_t max = get_long( address );
		uval_t len = get_long( address + 4 );
		//TODO: is 2000 high enoug?
		if( max >= len && (max < 2000) )
		{
			ea_t offset = get_long( address + 8 );
			if( isEnabled( offset ) )
			{
				const int val = 1;//MAGIC value
				fa.set_combobox_value( ID_PRESET, &val );
				return true;
			}
		}
	}

	//check for BER encoded number
	{
		if( get_BER_int_len( address ) != BADADDR )
		{
			const int val = 2;//MAGIC value
			fa.set_combobox_value( ID_PRESET, &val );
			return true;
		}
	}

	if( to_probe < 5 )
	{
		msg( "current item is too short" );
		return false;
	}


	std::unique_ptr<char> buffer = std::unique_ptr < char > {new char[ to_probe ]};
	if( !buffer.get() )
		return false;

	if( !get_many_bytes( address, buffer.get(), to_probe ) )
		return false;

	unsigned char * data = (unsigned char *)buffer.get();
	const size_t len = strlen( buffer.get() );
	size_t to_process = std::min( len, to_probe );

	bool ok;
	//skip BER and GMP
	for( size_t i = 2; i < arraysz( templates ); ++i )
	{
		const unsigned base = alphabets_lengths[ i - 2 ];
		reverse_table & table = reverse[ i - 2 ];

		ok = false;
		for( size_t j = 0; j < to_process; j++ )
		{
			const unsigned char b = data[ j ];
			const unsigned char ch = table[ b ];

			if( ch == 0xff )
			{
				if( (b == '=') && (base == 64) )
				{
					goto end;//ugly ugly!
				}
				ok = false;
				break;
			}

		end:
			if( j == to_process - 1 )
			{
				ok = true;
			}
		}
		if( ok )
		{
			//fa.set_chooser_value();
			//set_preset( fa, *templates[ i ] );
			//index to templates list .. must skip <none>
			const int val = i + 1;
			fa.set_combobox_value( ID_PRESET, &val );
			break;
		}
	}
	return true;
}

bool settings_t::dump( mpz_class &number )
{
	size_t to_dump = size();
	if( to_dump > 1000 )
	{
		msg( "number is too big!\n" );
		return false;
	}
	std::unique_ptr<char> buffer = std::unique_ptr < char > {new char[ to_dump ]};
	if( !buffer.get() )
		return false;
	if( !get_many_bytes( address, buffer.get(), to_dump ) )
		return false;
	number = 0;

	if( base_idx == 0 )
	{
		mpz_import( number.get_mpz_t(), length, bignum_endian, word_size, word_endian, 0, buffer.get() );
	}
	else
	{
		if( base_idx > nalphabets )
		{
			msg( "wrong base" );
			return false;
		}
		if( word_size != 1 )
		{
			//word_endian is therefore irrelevant
			msg( "Word size must be 1!" );
			return false;
		}
		unsigned base = alphabets_lengths[ base_idx - 1 ];

		//word_size and is irrelevant
		reverse_table & table = reverse[ base_idx - 1 ];
		const size_t len = strlen( buffer.get() );
		//sometimes there is final \0 byte in the string
		//sometimes there is not
		size_t to_process = std::min( len, to_dump );
		size_t start, stop, inc;
		switch( bignum_endian )
		{
			case 1:
				start = 0;
				stop = len;
				inc = 1;
				break;
			case -1:
				start = len - 1;
				stop = -1;
				inc = -1;
				break;
			default:
				msg( "wrong bignum endian %d!\n", bignum_endian );
				return false;
		}

		unsigned char * data = (unsigned char *)buffer.get();

		number = 0;
		for( int i = start; i != stop; i += inc )
		{
			const unsigned char b = data[ i ];
			const unsigned char ch = table[ b ];

			if( ch == 0xff )
			{
				if( (b == '=') && (base == 64) )
				{
					number >>= 2;
					continue;
				}
				break;
			}
			number = number*base + ch;
		}
	}

	return true;
}


static void init_dumper_form( form_actions_t &fa )
{
	settings_t s;
	if( !s.read_settings( fa ) )
		return;

	qstring example = s.make_example();
	fa.set_label_value( ID_EXAMPLE, example.c_str() );
}


bool set_preset( form_actions_t &fa, settings_t & settings )
{
	int word_size_idx = settings.word_size_idx();
	int word_endian_idx = settings.word_endian_idx();
	int bignum_endian_idx = settings.bignum_endian_idx();
	int base_idx = settings.base_idx;

	if( !fa.set_ascii_value( ID_ADDRESS, settings.address_text ) )
		return false;

	if( !fa.set_ascii_value( ID_WORDS, settings.length_text ) )
		return false;

	if( !fa.set_combobox_value( ID_WORD_SIZE, &word_size_idx ) )
		return false;
	if( !fa.set_combobox_value( ID_WORD_ENDIAN, &word_endian_idx ) )
		return false;

	if( !fa.set_combobox_value( ID_BIGNUM_ENDIAN, &bignum_endian_idx ) )
		return false;

	if( !fa.set_combobox_value( ID_BASE, &base_idx ) )
		return false;
	return true;
}

static bool saved = false;

static void save()
{
	char * path = askfile_c( 1, "numbers.txt", "where do you want to save it?" );
	if( !path )
		return;

	FILE * f = fopenWT( path );
	if( !f )
	{
		msg( "Could not open file %s for writing!", path );
		return;
	}
	for each (const mpz_class & n in number_list)
	{
		std::stringstream ss;
		ss << n << std::endl;

		std::string s = ss.str();
		if( qfwrite( f, s.c_str(), s.length() ) != s.length() )
			break;
	}
	qfclose( f );
}

static bool load()
{
	char * path = askfile_c( 0, "*.txt", "Which file to load?" );
	if( !path )
		return false;
	FILE * f = fopenRT( path );
	if( !f )
	{
		msg( "Could not open file %s for reading!", path );
		return false;
	}
	number_list.clear();
	char line[ 2 * MAXSTR ] = { 0 };
	while( qfgets( line, sizeof( line ), f ) != NULL )
	{
		try
		{
			mpz_class c( line );
			push_number( c, false );
		}
		catch( std::exception e )
		{

		}
	}
	qfclose( f );
	return true;
}

//--------------------------------------------------------------------------
// this callback is called when something happens in our non-modal editor form
static int idaapi dumper_window_cb( int fid, form_actions_t &fa )
{
	switch( fid )
	{
		case CB_INIT:     // Initialization
		{
			init_dumper_form( fa );
			g_fa = &fa;
			break;
		}
		case CB_CLOSE:    // Closing the form
		{
			g_fa = 0;
			// mark the form as closed
			editor_tform = NULL;
			// If control form exists then update buttons
			break;
		}

			//TODO: move these numbers into enum
		case ID_ADDRESS:
			break;

		case ID_WORDS:
		case ID_WORD_SIZE:
		case ID_WORD_ENDIAN:
		case ID_BIGNUM_ENDIAN:
		case ID_BASE:
		{
			init_dumper_form( fa );
			break;
		}
			//preset changed
		case ID_PRESET:
		{
			int selected = 0;
			static int last_selected = 0;
			static settings_t last;

			if( !fa.get_combobox_value( ID_PRESET, &selected ) )
			{
				break;
			}


			if( (last_selected == 0) && (selected != 0) )
			{
				last.read_settings( fa );
			}

			switch( selected )
			{
				case 0:
					//save current preset
					if( last_selected != 0 )
					{
						set_preset( fa, last );
					}
					break;

				case 1:
				{
					set_preset( fa, mpir_32_template );
					break;
				}
				case 2:
				{
					set_preset( fa, mpir_BER_template );
					break;
				}

				default:
				{
					if( selected - 1 < arraysz( templates ) )
					{
						set_preset( fa, *templates[ selected - 1 ] );
					}
					else
					{
						if( (selected < 0) || (presets.size() >= selected) )
						{
							msg( "todo: preset #%d\n", selected );
						}
						else
						{
							msg( "todo: preset %s\n", presets[ selected ].c_str() );
						}
					}
					break;
				}
			}
			last_selected = selected;
			break;
		}

		case ID_SAVE:
			//save
			save();
			break;
		case ID_LOAD:
			//load
			if( load() )
			{
				fa.refresh_field( ID_BIGNUM_LIST );
			}
			break;

		case ID_GUESS_TYPE:
		{
			guess_template( fa );
			break;
		}


		case ID_REFRESH:
			fa.refresh_field( ID_BIGNUM_LIST );
			break;

		case ID_BIGNUM_LIST:
			//messages from list of numbers
			break;

		case ID_GUESS:
			if( number_list.size() < 3 )
			{
				msg( "at least three numbers needed!" );
			}
			else
			{
				show_wait_box( "get yourself a coffee or two, this could take some time..." );

				try
				{
					std::string log = guess_relations( number_list );
					msg( "%s\n", log.c_str() );
				}
				catch( ... )
				{

				}

				hide_wait_box();
			}
			break;

		case ID_DUMP:
		{
			settings_t s;
			if( !s.read_settings( fa ) )
				break;
			mpz_class number;
			if( !s.dump( number ) )
				break;
			push_number( number );
			break;
		}

		case ID_GEN_IDC:
		{
			settings_t s;
			if( !s.read_settings( fa ) )
				break;
			msg( "code: dump( %s, %s, %d, %d, %d, %d )\n", s.address_text, s.length_text, s.word_size, s.base_idx, s.word_endian, s.bignum_endian );
			break;
		}
		case ID_EXAMPLE:
			//(probably wont happen)
			//silence!
			break;
		default:
		{
			msg( "unknown id %d\n", fid );
			break;
		}
	}
	return 1;
}

static int idaapi dump_cb( TView *[], int )
{
	//msg( "Dump button has been pressed -> " );
	return 0;
}


static int idaapi guess_cb( TView *[], int )
{
	//msg( "Dump button has been pressed -> " );
	return 0;
}

static int idaapi save_cb( TView *[], int )
{
	//msg( "Dump button has been pressed -> " );
	return 0;
}

static int idaapi load_cb( TView *[], int )
{
	//msg( "Dump button has been pressed -> " );
	return 0;
}

static int idaapi gen_cb( TView *[], int )
{
	//msg( "Dump button has been pressed -> " );
	return 0;
}

static int idaapi refresh_cb( TView *[], int )
{
	//msg( "Dump button has been pressed -> " );
	return 0;
}

//---------------------------------------------------------------------------
// chooser: return the text to display at line 'n' (0 returns the column header)
static void idaapi getl( void *, uint32 n, char * const *arrptr )
{

	if( n == 0 )
	{
		qstrncpy( arrptr[ 0 ], "number", MAXSTR );
		qstrncpy( arrptr[ 1 ], "hex", MAXSTR );
		qstrncpy( arrptr[ 2 ], "prime?", MAXSTR );
		qstrncpy( arrptr[ 3 ], "bits", MAXSTR );
	}
	else
	{
		size_t pos = n - 1;

		if( pos < number_list.size() )
		{
			std::string s;
			std::stringstream ss;
			mpz_class & number = number_list[ pos ];

			ss << number;
			s = ss.str();

			qstrncpy( arrptr[ 0 ], s.c_str(), MAXSTR );

			ss.str( std::string() );

			ss << std::hex << number;

			s = ss.str();
			qstrncpy( arrptr[ 1 ], s.c_str(), MAXSTR );

			//mpz_likely_prime_p();
			qstrncpy( arrptr[ 2 ], mpz_probab_prime_p( number.get_mpz_t(), 8 ) ? "yes" : "no", MAXSTR );

			int bits = mpz_sizeinbase( number.get_mpz_t(), 2 );
			qstring qbits;
			qbits.cat_sprnt( "%d", bits );
			qstrncpy( arrptr[ 3 ], qbits.c_str(), MAXSTR );
		}
		else
		{
			qstrncpy( arrptr[ 0 ], "error", MAXSTR );
		}
	}


}

static uint32 idaapi del( void *obj, uint32 n )
{
	try// with std::advance one can never be too carefull
	{
		number_list_t::iterator i = number_list.begin();
		std::advance( i, n - 1 );
		number_list.erase( i );
	}
	catch( ... )
	{
	}
	return 1;
}

static void idaapi ins( void *obj )
{
	int value = 0;
	char * answer = askstr( HIST_NUM, (char*)&value, "Enter a decimal number" );

	if( answer )
	{
		try
		{
			int x = *(int *)answer;
			mpz_class number( x );
			push_number( number );
		}
		catch( ... )
		{
			msg( "exception!\n" );
		}

	}
}

//---------------------------------------------------------------------------
// chooser: return the number of lines in the list
static uint32 idaapi sizer( void * )
{
	return number_list.size();
}

//---------------------------------------------------------------------------
// create and open the editor form
static void open_dumper_form( int options = 0 )
{
	static const char formdef[] =
		"BUTTON NO NONE\n"        // we do not want the standard buttons on the form
		"BUTTON YES NONE\n"
		"BUTTON CANCEL NONE\n"
		"Bignum dumper\n"           // the form title. it is also used to refer to the form later
		"\n"
		"%/"                      // placeholder for the 'dumper_window_cb' callback
		"<preset:" CMD_DROPDOWN( ID_PRESET ) ":0::::>\n"     // preset
		"<#Address of the bignum in memory. You can use and idc expression here.#address:" CMD_ASCII( ID_ADDRESS ) ":::::> "     // address
		"<#Tries to guess template of bignum at this address. Works only with textual types#guess template:" CMD_BUTTON( ID_GUESS_TYPE ) ":::::>\n" // guess type button
		"<#Number of words in the bignum. You can use and idc expression here.#words:" CMD_ASCII( ID_WORDS ) ":::::>\n" // length of bignum (in words)
		"<#Size of the word in bignum.#word size:" CMD_DROPDOWN( ID_WORD_SIZE ) ":0::::>\n" // size of one bignum word
		"<#filter to use for dumping.#base:" CMD_DROPDOWN( ID_BASE ) ":0::::>\n" // base
		"<#Endianess of every singe word in bignum.#word endian:" CMD_DROPDOWN( ID_WORD_ENDIAN ) ":0::::>\n" // word endian
		"<#Endianess of the whole number.#bignum endian:" CMD_DROPDOWN( ID_BIGNUM_ENDIAN ) ":0::::>\n" // bignum endian
		"\nexample: " CMD_LABELA( ID_EXAMPLE ) "\n" // example
		"<#Dumps bignum from memory into bignums list.#dump:" CMD_BUTTON( ID_DUMP ) ":::::>" // dump button
		"<#Tries to guess formulas for current list of bignums.#guess:" CMD_BUTTON( ID_GUESS ) ":::::>" // guess button
		"<#Save current bignum list to text file.#save:" CMD_BUTTON( ID_SAVE ) ":::::>" // save button
		"<#Load bignums from text file.#load:" CMD_BUTTON( ID_LOAD ) ":::::>" // load button
		"<#This will write an idc command to dump bignum with current configuration to console. Stick it this into breakpoint or so.#idc expression:" CMD_BUTTON( ID_GEN_IDC ) ":::::>" // gen idc button
		//		"<#If you use dump idc command the bignum list is not automatically refreshed. To fix it uset this button.#refresh list:" CMD_BUTTON(ID_REFRESH) ":::::>\n" // manual refresh
		"<numbers:" CMD_CHOOSE( ID_BIGNUM_LIST ) ":::::>\n" // bignum list
		;

	// structure for chooser list view
	chooser_info_t chi = { 0 };
	chi.cb = sizeof( chooser_info_t );
	chi.columns = 4;
	chi.getl = getl;
	chi.sizer = sizer;
	chi.title = CHOOSER_NOSTATUSBAR;
	static const int widths[] = { 30, 30, 4, 4 };
	chi.widths = widths;
	chi.width = 140;
	chi.icon = -1;
	chi.del = del;
	chi.ins = ins;

	// selection for chooser list view
	intvec_t selected;

	//sval_t addr = get_screen_ea();
	char * len = "4";
	char * addr = "here";

	int selection = 0;
	editor_tform = OpenForm_c( formdef,
		FORM_QWIDGET | options,
		dumper_window_cb,
		&presets, &selection,//preset
		addr,//default value for address
		dump_cb,//guess type button
		len, // default value for length
		&word_size, &selection,
		&basis, &selection,
		&endian, &selection,
		&endian, &selection,
		"1 = [01]",
		dump_cb,
		guess_cb,
		save_cb,
		load_cb,
		gen_cb,
		//		refresh_cb,
		&chi, &selected
		);
}

//--------------------------------------------------------------------------
// the main function of the plugin
static void idaapi run( int )
{
	// first open the editor form
	open_dumper_form( FORM_RESTORE );
	//set_dock_pos( "Control form", NULL, DP_FLOATING, 0, 0, 300, 100 );
}


//--------------------------------------------------------------------------
// initialize the plugin
static int idaapi init( void )
{
	// we always agree to work.
	// we must return PLUGIN_KEEP because we will install callbacks.
	// if we return PLUGIN_OK, the kernel may unload us at any time and this will
	// lead to crashes.

	initme();

	register_idc_functions();

	addon_info_t addon;
	addon.id = "milan.bohacek.bignum.dumper";
	addon.name = "Bignum dumper";
	addon.producer = "Milan Bohacek";
	addon.url = "";
	addon.version = VERSION;
	addon.freeform =
		"Copyright (c) 2005 - 2014 Milan Bohacek <milan.bohacek+bignum@gmail.com>\n"
		"All rights reserved.\n";
	register_addon( &addon );
	msg( "Bignum dumper " VERSION " (c) Milan Bohacek <milan.bohacek+bignum@gmail.com>\n" );
	return PLUGIN_KEEP;
}

static void idaapi term( void )
{
	unregister_idc_functions();
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	0,
	init,                 // initialize
	term,                 // terminate. this pointer may be NULL.
	run,                  // invoke plugin
	NULL,                 // long comment about the plugin
	NULL,                 // multiline help about the plugin
	"~B~ignum dumper",// the preferred short name of the plugin
	NULL                  // the preferred hotkey to run the plugin
};

bool wasbreak( void )
{
	return wasBreak();
}

// ea -> pointer to the beginning of BER encoded INTEGER
static asize_t get_BER_int_len( ea_t ea )
{
	if( !isEnabled( ea ) )
		return BADADDR;
	//skip tag
	uchar t = get_byte( ea );
	if( t != 2 )
		return BADADDR;
	ea += 1;
	asize_t len = 0;
	uchar l;

	l = get_byte( ea++ );
	if( (l & 0x80) == 0 )
		return l;

	l = l & 0x7f;
	for( asize_t j = 0; j < l; ++j )
	{
		uchar d = get_byte( ea++ );
		len = (len << 8) | d;
	}
	return len;
}

// ea -> pointer to the beginning of BER encoded INTEGER
static asize_t get_BER_int_offset( ea_t ea )
{
	if( !isEnabled( ea ) )
		return BADADDR;
	//skip tag
	uchar t = get_byte( ea );
	if( t != 2 )
		return BADADDR;
	++ea;
	asize_t len = 0;
	uchar l = get_byte( ea++ );

	if( (l & 0x80) == 0 )
		return ea;

	l = l & 0x7f;
	return ea + l;
}

static const char dump_idc_args[] = { VT_LONG, VT_LONG, VT_LONG, VT_LONG, VT_LONG, VT_LONG, 0 };

static error_t idaapi dump_idc( idc_value_t *argv, idc_value_t *res )
{
	msg( "dump_idc is called with arg0=%" FMT_EA "x\n", argv[ 0 ].num );
	//argv[ 0 ].num


	settings_t s;
	s.address = argv[ 0 ].num;
	s.length = argv[ 1 ].num;
	s.word_size = argv[ 2 ].num;
	s.base_idx = argv[ 3 ].num;
	s.word_endian = argv[ 4 ].num;
	s.bignum_endian = argv[ 5 ].num;
	mpz_class number;
	if( s.dump( number ) )
		push_number( number );
	return eOk;
}

static const char idc_BER_length_args[] = { VT_LONG, 0 };

static error_t idaapi idc_BER_length( idc_value_t *argv, idc_value_t *res )
{
	ea_t ea = argv[ 0 ].num;

	asize_t len = get_BER_int_len( ea );
	res->set_long( len );
	return eOk;
}

static const char idc_BER_offset_args[] = { VT_LONG, 0 };

static error_t idaapi idc_BER_offset( idc_value_t *argv, idc_value_t *res )
{
	ea_t ea = argv[ 0 ].num;

	asize_t len = get_BER_int_offset( ea );
	res->set_long( len );
	return eOk;
}

void unregister_idc_functions()
{
	set_idc_func_ex( "dump", NULL, NULL, 0 );
	set_idc_func_ex( "BER_int_length", NULL, NULL, 0 );
	set_idc_func_ex( "BER_int_offset", NULL, NULL, 0 );
}

void register_idc_functions()
{
	set_idc_func_ex( "dump", dump_idc, dump_idc_args, EXTFUN_BASE );
	set_idc_func_ex( "BER_int_length", idc_BER_length, idc_BER_length_args, EXTFUN_BASE );
	set_idc_func_ex( "BER_int_offset", idc_BER_offset, idc_BER_offset_args, EXTFUN_BASE );
}
