package shop.HealthJava.vo;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AddrVO {

	/*-- 배송지 table 
	create table tbl_addr (
	    addr_no NUMBER primary key, -- 주소 no 
	    user_id VARCHAR2(100) , --회원 id
	    postCode varchar2(100) , -- 회원 우편번호
	    roadAddr varchar2(100) ,-- 회원 도로명 주소
	    detailAddr varchar2(100) , -- 회원 상세 주소
	    addr_name varchar2(100) -- 배송지 별명
	);
	 */
	
	private int addr_no;
	private String user_id;
	private String postCode;
	private String roadAddr;
	private String detailAddr;
	private String addr_name;
	
}
