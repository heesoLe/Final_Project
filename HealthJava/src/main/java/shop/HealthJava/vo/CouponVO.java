package shop.HealthJava.vo;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class CouponVO {
	
	/*-- 쿠폰 table 
	create table tbl_coupon (
	    coupon_no NUMBER PRIMARY KEY , -- 쿠폰 no
	    coupon_name VARCHAR2(100) , --쿠폰명
	    coupon_dc NUMBER(38) ,-- 쿠폰
	    coupon_mem_id VARCHAR(100) REFERENCES tbl_member(user_id)  -- 회원 아이디 , 비회원 아이디 :랜덤값  : F
	);*/
	
	private int coupon_no; // 쿠폰 no
	private String coupon_name; // 쿠폰명
	private int coupon_dc; // 쿠폰할인율
	private String coupon_mem_id; // 회원아읻, 비회원아이디 (랜덤값)
}
