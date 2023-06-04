package shop.HealthJava.vo;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ReviewsVO {
	
	/*-- 상품 후기 table 
	create table tbl_reviews (
	    re_no NUMBER PRIMARY KEY , -- 후기 no
	    re_pro_no NUMBER(38) REFERENCES tbl_product(product_no) , --제품no : F
	    re_mem_id VARCHAR2(100) , -- 회원 아이디 
	    re_title VARCHAR2(100) , -- 리뷰 제목
	    re_content VARCHAR2(4000) ,  --리뷰 내용
	    re_image1 VARCHAR2(4000)  , --사진 등록1
	    re_image2 VARCHAR2(4000)  , -- 사진등록2
	    re_image3 VARCHAR2(4000)  , -- 사진등록3
	    re_score NUMBER(38) , --별점 score
	    re_date DATE --등록일
	);
	*/

	private int re_no; // 후기no
	private int re_pro_no; // 제품 no
	private String re_mem_id; // 회원 아이디
	private String re_title; // 후기 제목
	private String re_content; // 후기 내용
	private String re_image1; // 사진등록 1
	private String re_image2; // 사진등록 2
	private String re_image3; // 사진등록 3
	private int re_score; // 리뷰 별점 
	private String re_date; // 등록일
}
