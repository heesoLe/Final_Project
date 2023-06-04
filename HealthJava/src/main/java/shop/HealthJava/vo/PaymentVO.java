package shop.HealthJava.vo;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class PaymentVO {
	
	/*-- 결제 table 생성
	create table tbl_pay (
	    pay_no NUMBER PRIMARY KEY , -- 주문번호 no
	    pay_id VARCHAR2(100) , -- 회원 1, 비회원 2
	    pay_date DATE , -- 주문일자 
	    pay_name VARCHAR2(100) , -- 수령자 
	    pay_phone VARCHAR2(100) ,-- 수령자 연락처 
	    pay_post VARCHAR2(100) , -- 수령자 우편번호 
	    pay_road VARCHAR2(100) , -- 수령자 주소 
	    pay_detail VARCHAR2(100) , -- 수령자 상세주소
	    pay_total NUMBER(38) , -- 총 금액
	    pay_type NUMBER(38) -- 결제 수단 : 1 무통장금액_메일발송안내, 2 카드결제 3. 카카오페이/네이버페이 
	);*/

	private int pay_no; 
	private String pay_id;
	private String pay_date;
	private String pay_name;
	private String pay_phone;
	private String pay_post;
	private String pay_road; 
	private String pay_detail;
	private int pay_total;
	private int pay_type;
	
}
