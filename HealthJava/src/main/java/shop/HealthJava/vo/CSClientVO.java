package shop.HealthJava.vo;

import lombok.Data;

@Data
public class CSClientVO {
	
	private int client_no; //고객 문의 글 번호
	private String client_title; //고객 문의 글 제목
	private String client_cont; //고객 문의 글 내용
	private String client_cont_reply; //고객 문의 글 답변 내용
	private String client_category; // 회원정보, 상품확인, 주문/결제, 배송, 교환/취소/반품, 서비스
	private String client_date; //고객 문의 글 작성 날짜(sysdate)
	private String user_id; //회원아이디(fk)
	private String contact_password; //1대1 문의글 비번 
	
	// 관리자 회원목록에서 페이징(쪽나누기) 관련변수
	private int startrow; // 시작행 번호
	private int endrow; // 끝행번호
	
	//검색필드
	private String search_type; //검색 필터(타입)
	private String search_field; //검색 입력필드

}
