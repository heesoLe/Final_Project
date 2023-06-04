package shop.HealthJava.vo;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class CartVO {
	
	/*-- 장바구니 table
	create table tbl_cart (
	   cart_no NUMBER PRIMARY KEY , -- 장바구니 no
	   cart_mem_id VARCHAR2(100) REFERENCES tbl_member(user_id) , -- 회원 아이디 , 비회원 아이디 :랜덤값 
	   cart_pro_no NUMBER(38) REFERENCES tbl_product(product_no)  , -- 제품 고유번호 : F 상품no
	   cart_cnt  NUMBER(38) , -- 구매 수량
	   product_cont1 varchar2(4000) , -- 상품이미지
	   product_title varchar2(100) , -- 상품명
	   product_price varchar2(100)  -- 상품 가격
	);*/
	
	private int cart_no; // 장바구니 no
	private String cart_mem_id; // 회원아이디, 비회원일 때 : 랜덤값
	private int cart_pro_no; // 제품 no
	private int cart_cnt; // 구매 수량
	
	private String product_cont1; // 상품이미지1
	private String product_title; // 상품명
	private String product_price; //가격
}
