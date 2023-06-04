package shop.HealthJava.vo;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class RefundVO {
	
	/*-- 교환, 환불 table : 신청용
	create table tbl_refund (
	    refund_no NUMBER PRIMARY KEY , -- 교환, 환불 no
	    refund_order_no NUMBER PRIMARY KEY  REFERENCES tbl_product(product_no) , -- 주문번호 no : F = 상품no
	    refund_category VARCHAR2(100) , -- 카테고리 : 1.교환, 2. 환불, 3.기타
	    refund_cont VARCHAR2(4000) , -- 사유(내용) 
	    refund_image varchar2(1000) , --사진
	    refund_state varchar2(100) , -- 상태 : 1대기, 2접수중, 3접수완료 
	    refund_date DATE -- 등록일자
	);*/
	
	private int refund_no; // 교환, 환불 no
	private int refund_order_no; // 제품 no
	private String refund_category; // 카테고리 : 1.교환, 2.환불. 3.기타
	private String refund_cont; // 사유(내용)
	private String refund_image; // 사진
	private String refund_state; // 상태 : 1.대기, 2.접수중, 3.접수완료
	private String date; // 등록일자 
	
}
