package shop.HealthJava.vo;

import lombok.Data;

@Data
public class CSNoticeVO {
	private int notice_no;
	private String notice_title;
	private String notice_cont;
	private String notice_date;
	
	private int startrow;
	private int endrow;
	
	private String search_type;// 검색어
	private String search_field;// 검색 필드
}
