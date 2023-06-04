package shop.HealthJava.vo;

import lombok.Data;

@Data
//<<<<<<< Updated upstream
public class ProductQnAVO {

	private int qna_no;
	private int qna_product_no;
	private String qna_mem_id;
	private String qna_title;
	private String qna_content;
	private String qna_reply;
	private String qna_date; //상품 문의 글 작성 날짜(sysdate)

	//검색필드
	private String search_type; //검색 필터(타입)
	private String search_field; //검색 입력필드

//=======

}
