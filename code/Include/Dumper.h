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

#pragma once
#define arraysz(x) (sizeof(x) / sizeof(*x))

typedef std::vector < mpz_class > number_list_t;
extern std::string guess_relations( number_list_t & numbers );
extern bool wasbreak( void );