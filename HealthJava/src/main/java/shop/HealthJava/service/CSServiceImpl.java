package shop.HealthJava.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import shop.HealthJava.dao.CSDAO;
import shop.HealthJava.vo.CSClientVO;
import shop.HealthJava.vo.CSFAQVO;
import shop.HealthJava.vo.CSNoticeVO;
import shop.HealthJava.vo.MemberVO;

@Service
public class CSServiceImpl implements CSService {
	
	@Autowired
	private CSDAO csDao;

	//CS - 공지사항 글 개수
	@Override
	public int getNoticeListCount(CSNoticeVO nvo) {
		return this.csDao.getNoticeListCount(nvo);
	}

	//CS - 공지사항 목록
	@Override
	public List<CSNoticeVO> getCSNoticeList(int page, int limit, CSNoticeVO nvo) {
		return this.csDao.getCSNoticeList(page, limit, nvo);
	}

	//CS - 공지사항 글 작성
	@Override
	public void insertNotice(CSNoticeVO nvo) {
		this.csDao.insertNotice(nvo);
	}
	
	//CS - FAQ 목록
	@Override
	public List<CSFAQVO> getCSFAQList(String faq_category) {
		return this.csDao.getCSFAQList(faq_category);
	}

	//CS - FAQ 글 작성
	@Override
	public void insertFAQ(CSFAQVO cvo) {
		this.csDao.insertFAQ(cvo);
	}

	//CS - 1대1 문의글 목록 조회
	@Override
	public List<CSClientVO> getCSClientList() {
		return this.csDao.getCSClientList();
	}

	//CS - 1대1 문의글 작성
	@Override
	public void insertContact(CSClientVO cvo) {
		this.csDao.insertContact(cvo);
	}

	//CS - 1대1 문의글 내용보기
	@Override
	public CSClientVO getClientCont(int client_no) {
		return this.csDao.getClientCont(client_no);
	}



	
}