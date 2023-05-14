#pragma once

#include <z3++.h>

class x8664_ctx
{
public:
	z3::expr* rax;
	z3::expr* rbx;
	z3::expr* rcx;
	z3::expr* rdx;
	z3::expr* rbp;
	z3::expr* rsp;
	z3::expr* rsi;
	z3::expr* rdi;
	z3::expr* r8;
	z3::expr* r9;
	z3::expr* r10;
	z3::expr* r11;
	z3::expr* r12;
	z3::expr* r13;
	z3::expr* r14;
	z3::expr* r15;

	z3::expr* rip;
	z3::expr* rflags;

	z3::expr* xmm0;
	z3::expr* xmm1;
	z3::expr* xmm2;
	z3::expr* xmm3;
	z3::expr* xmm4;
	z3::expr* xmm5;
	z3::expr* xmm6;
	z3::expr* xmm7;
	z3::expr* xmm8;
	z3::expr* xmm9;
	z3::expr* xmm10;
	z3::expr* xmm11;
	z3::expr* xmm12;
	z3::expr* xmm13;
	z3::expr* xmm14;
	z3::expr* xmm15;

	z3::expr* zf;
	z3::expr* of;
	z3::expr* cf;
	z3::expr* pf;
	z3::expr* sf;
	z3::expr* af;
	z3::expr* df;

	std::list<z3::expr*> immediate;

	inline x8664_ctx()
		: rax(nullptr)
		, rbx(nullptr)
		, rcx(nullptr)
		, rdx(nullptr)
		, rbp(nullptr)
		, rsp(nullptr)
		, rsi(nullptr)
		, rdi(nullptr)
		, r8(nullptr)
		, r9(nullptr)
		, r10(nullptr)
		, r11(nullptr)
		, r12(nullptr)
		, r13(nullptr)
		, r14(nullptr)
		, r15(nullptr)

		, rip(nullptr)
		, rflags(nullptr)

		, xmm0(nullptr)
		, xmm1(nullptr)
		, xmm2(nullptr)
		, xmm3(nullptr)
		, xmm4(nullptr)
		, xmm5(nullptr)
		, xmm6(nullptr)
		, xmm7(nullptr)
		, xmm8(nullptr)
		, xmm9(nullptr)
		, xmm10(nullptr)
		, xmm11(nullptr)
		, xmm12(nullptr)
		, xmm13(nullptr)
		, xmm14(nullptr)
		, xmm15(nullptr)

		, zf(nullptr)
		, of(nullptr)
		, cf(nullptr)
		, pf(nullptr)
		, sf(nullptr)
		, af(nullptr)
		, df(nullptr)
	{}

	inline void create_initial_state(z3::context& z3c, x8664_ctx& ctx)
	{
		ctx.rax = new z3::expr(z3c.bv_const("init_rax", 64));
		ctx.rbx = new z3::expr(z3c.bv_const("init_rbx", 64));
		ctx.rcx = new z3::expr(z3c.bv_const("init_rcx", 64));
		ctx.rdx = new z3::expr(z3c.bv_const("init_rdx", 64));
		ctx.rbp = new z3::expr(z3c.bv_const("init_rbp", 64));
		ctx.rsp = new z3::expr(z3c.bv_const("init_rsp", 64));
		ctx.rsi = new z3::expr(z3c.bv_const("init_rsi", 64));
		ctx.rdi = new z3::expr(z3c.bv_const("init_rdi", 64));
		ctx.r8 = new z3::expr(z3c.bv_const("init_r8", 64));
		ctx.r9 = new z3::expr(z3c.bv_const("init_r9", 64));
		ctx.r10 = new z3::expr(z3c.bv_const("init_r10", 64));
		ctx.r11 = new z3::expr(z3c.bv_const("init_r11", 64));
		ctx.r12 = new z3::expr(z3c.bv_const("init_r12", 64));
		ctx.r13 = new z3::expr(z3c.bv_const("init_r13", 64));
		ctx.r14 = new z3::expr(z3c.bv_const("init_r14", 64));
		ctx.r15 = new z3::expr(z3c.bv_const("init_r15", 64));
		ctx.rip = new z3::expr(z3c.bv_const("init_rip", 64));
		ctx.rflags = new z3::expr(z3c.bv_const("init_rflags", 64));

		ctx.xmm0 = new z3::expr(z3c.bv_const("init_xmm0", 128));
		ctx.xmm1 = new z3::expr(z3c.bv_const("init_xmm1", 128));
		ctx.xmm2 = new z3::expr(z3c.bv_const("init_xmm2", 128));
		ctx.xmm3 = new z3::expr(z3c.bv_const("init_xmm3", 128));
		ctx.xmm4 = new z3::expr(z3c.bv_const("init_xmm4", 128));
		ctx.xmm5 = new z3::expr(z3c.bv_const("init_xmm5", 128));
		ctx.xmm6 = new z3::expr(z3c.bv_const("init_xmm6", 128));
		ctx.xmm7 = new z3::expr(z3c.bv_const("init_xmm7", 128));
		ctx.xmm8 = new z3::expr(z3c.bv_const("init_xmm8", 128));
		ctx.xmm9 = new z3::expr(z3c.bv_const("init_xmm9", 128));
		ctx.xmm10 = new z3::expr(z3c.bv_const("init_xmm10", 128));
		ctx.xmm11 = new z3::expr(z3c.bv_const("init_xmm11", 128));
		ctx.xmm12 = new z3::expr(z3c.bv_const("init_xmm12", 128));
		ctx.xmm13 = new z3::expr(z3c.bv_const("init_xmm13", 128));
		ctx.xmm14 = new z3::expr(z3c.bv_const("init_xmm14", 128));
		ctx.xmm15 = new z3::expr(z3c.bv_const("init_xmm15", 128));

		ctx.zf = new z3::expr(z3c.bool_const("init_zf"));
		ctx.of = new z3::expr(z3c.bool_const("init_of"));
		ctx.cf = new z3::expr(z3c.bool_const("init_cf"));
		ctx.pf = new z3::expr(z3c.bool_const("init_pf"));
		ctx.sf = new z3::expr(z3c.bool_const("init_sf"));
		ctx.af = new z3::expr(z3c.bool_const("init_af"));
		ctx.df = new z3::expr(z3c.bool_const("init_df"));
	}

	#define check_and_copy(var_name) if (new_state.var_name) old_state.var_name = new_state.var_name;

	inline void copy_changed_state(x8664_ctx& old_state, x8664_ctx& new_state)
	{
		check_and_copy(rax);
		check_and_copy(rbx);
		check_and_copy(rcx);
		check_and_copy(rdx);
		check_and_copy(rbp);
		check_and_copy(rsp);
		check_and_copy(rsi);
		check_and_copy(rdi);
		check_and_copy(r8);
		check_and_copy(r9);
		check_and_copy(r10);
		check_and_copy(r11);
		check_and_copy(r12);
		check_and_copy(r13);
		check_and_copy(r14);
		check_and_copy(r15);
		check_and_copy(rip);

		check_and_copy(rflags);

		check_and_copy(xmm0);
		check_and_copy(xmm1);
		check_and_copy(xmm2);
		check_and_copy(xmm3);
		check_and_copy(xmm4);
		check_and_copy(xmm5);
		check_and_copy(xmm6);
		check_and_copy(xmm7);
		check_and_copy(xmm8);
		check_and_copy(xmm9);
		check_and_copy(xmm10);
		check_and_copy(xmm12);
		check_and_copy(xmm13);
		check_and_copy(xmm14);
		check_and_copy(xmm15);

		check_and_copy(zf);
		check_and_copy(of);
		check_and_copy(cf);
		check_and_copy(pf);
		check_and_copy(sf);
		check_and_copy(af);
		check_and_copy(df);
	}

	#undef check_and_copy
};