package shop.HealthJava.vo;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class OrderVO {
	
	/* -- 주문내역(주문 목록) table 생성 
	CREATE TABLE tbl_order (
	    order_no NUMBER(38) PRIMARY KEY, -- 주문번호
	    order_product_title VARCHAR2(100) , --REFERENCES tbl_product(product_title), -- 상품명
	    order_date DATE,
	    order_cnt NUMBER, -- 수량
	    order_invoice VARCHAR2(100), -- 배송준비 완료시 : 송장번호 10자리 
	    order_total NUMBER(38) -- 총 금액
	);*/
		
	private int order_no; // 주문번호 no
	private String order_product_title; // 상품명
	private String order_date; // 주문일자
	private String order_cnt; // 수량
	private String order_invoice; // 송장번호 
	private int order_total; // 총 금액
	private String user_id; 
}
