package shop.HealthJava.vo;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class LikeVO {
	
	/*--  찜 목록 table 
	create table tbl_like (
	    like_no NUMBER PRIMARY KEY , -- 찜 no
	    like_mem_id VARCHAR(100) ,  --REFERENCES tbl_member(user_id)  , -- 회원ID : F
	    like_pro_id  NUMBER(38) REFERENCES tbl_product(product_no)  -- 제품 고유번호 : F = 상품no
	);
	*/
	
	private int like_no; // 찜no
	private String like_mem_id; // 회원 no _ user_id 불러오기 
	private int like_pro_no; // 제품 no
	
	//join 컬럼명
	private String product_no;
	private String product_title;
	private String Product_price;
	private String product_cont1;
	private String product_date;
}
