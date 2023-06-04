package shop.HealthJava.vo;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class OrderDetailVO {
	
	/*-- 주문상세내역 재 table 
	create table tbl_order_detail (
	    order_detail_no NUMBER PRIMARY KEY , -- 주문 no
	    order_no NUMBER(38) REFERENCES tbl_order(order_no)  , -- 주문내역 no
	    order_detail_mid VARCHAR2(100) REFERENCES tbl_member(user_id) ,
	    order_detail_fno NUMBER(38)  REFERENCES tbl_product(product_no) , -- 상품번호
	    order_detail_pname VARCHAR2(100) , -- 제품이름
	    order_detail_cnt VARCHAR2(100) , -- 수량 
	    order_detail_price VARCHAR2(100) -- 가격
	);*/
		
	private int order_detail_no; // 주문no
	private int order_no; // 주문내역 no
	private String order_detail_mid; //회원 아이디
	private int order_detail_fno; // 상품 no
	private String order_detail_cnt; // 수량
	
	
	private String order_detail_pname; // 제품명
	private String order_detail_price; // 금액
	
	private String user_id;
	private String product_title;
	private int product_no;
	private String order_detail_pcont;
	
	private String product_price;

}
