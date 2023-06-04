package shop.HealthJava.vo;

import lombok.Data;

@Data
public class ProductVO {

	private int product_no; //상품 글번호
	private String product_title; //상품명
	private String product_price; //상품 가격
	private String product_maker; //제조사
	private String product_type; //대분류
	private String product_type2; //소분류
	private String product_cont1; // 상품 내용(사진)
	private String product_cont2;
	private String product_cont3;
	private String product_cont4;
	private String product_cont5;
	private String product_cont6;
	private String product_cont7;
	private String product_cont8;
	private String product_score; // 별점
	private String product_count; // 재고
	private String product_date; //상품 등록날짜

	
	//페이징 쪽나누기 관련변수
    private int startrow;//시작행 번호
    private int endrow;//끝행 번호
    
    //검색기능
    private String search_type;//검색어
    private String search_field;//검색필드 
    
    
    //
    private int page_count;

}
