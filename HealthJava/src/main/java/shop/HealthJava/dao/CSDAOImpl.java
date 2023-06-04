package shop.HealthJava.dao;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import shop.HealthJava.vo.CSClientVO;
import shop.HealthJava.vo.CSFAQVO;
import shop.HealthJava.vo.CSNoticeVO;
import shop.HealthJava.vo.MemberVO;

@Repository
public class CSDAOImpl implements CSDAO {
	
	
	
	@Autowired
	private SqlSession sqlSession;

	//CS - 공지사항 글 개수
	@Override 
	public int getNoticeListCount(CSNoticeVO nvo) {
		return this.sqlSession.selectOne("notice_count", nvo);
	}

	//CS - 공지사항 목록
	@Override
	public List<CSNoticeVO> getCSNoticeList(int page, int limit, CSNoticeVO nvo) {
		  int startrow = (page - 1) * limit + 1; // 시작 레코드 번호 계산
		  int endrow = startrow + limit - 1; // 종료 레코드 번호 계산

		  Map<String, Object> map = new HashMap<>();
		  map.put("startrow", startrow);
		  map.put("endrow", endrow);
		  map.put("search_type", nvo.getSearch_type());
		  map.put("search_field", nvo.getSearch_field());

		  return sqlSession.selectList("notice_list", map);
	}
	
	//CS - 공지사항 글 작성
	@Override
	public void insertNotice(CSNoticeVO nvo) {
		this.sqlSession.insert("notice_write", nvo);
	}

	//CS - FAQ 목록
	@Override
	public List<CSFAQVO> getCSFAQList(String faq_category) {
		return this.sqlSession.selectList("faq_list", faq_category);
	}
	
	//CS - FAQ 글 작성
	@Override
	public void insertFAQ(CSFAQVO cvo) {
		this.sqlSession.insert("faq_write", cvo);
	}

	//CS - 1대1 문의글 목록 조회
	@Override
	public List<CSClientVO> getCSClientList() {
		return this.sqlSession.selectList("contact_list");
	}

	//CS - 1대1 문의글 작성
	@Override
	public void insertContact(CSClientVO cvo) {
		this.sqlSession.insert("contact_write", cvo);
	}

	//CS - 1대1 문의글 내용보기
	@Override
	public CSClientVO getClientCont(int client_no) {
		return this.sqlSession.selectOne("contact_cont", client_no);
	}

	
}