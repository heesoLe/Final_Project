package shop.HealthJava.dao;

import java.util.List;

import shop.HealthJava.vo.CSClientVO;
import shop.HealthJava.vo.CSFAQVO;
import shop.HealthJava.vo.CSNoticeVO;
import shop.HealthJava.vo.MemberVO;

public interface CSDAO {

	//CS - 공지사항 글 개수
	int getNoticeListCount(CSNoticeVO nvo);

	//CS - 공지사항 목록
	List<CSNoticeVO> getCSNoticeList(int page, int limit, CSNoticeVO nvo);
	
	//CS - 공지사항 글 작성
	void insertNotice(CSNoticeVO nvo);

	//CS - FAQ 목록
	List<CSFAQVO> getCSFAQList(String faq_category);

	//CS - FAQ 글 작성
	void insertFAQ(CSFAQVO cvo);

	//CS - 1대1 문의글 목록 조회
	List<CSClientVO> getCSClientList();

	//CS - 1대1 문의글 작성
	void insertContact(CSClientVO cvo);

	//CS - 1대1 문의글 내용보기
	CSClientVO getClientCont(int client_no);

	
	


}