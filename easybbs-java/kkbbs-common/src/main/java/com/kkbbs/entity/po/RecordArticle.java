package com.kkbbs.entity.po;

import java.io.Serializable;

public class RecordArticle implements Serializable {
    /**
     * 文章ID
     */
    private String articleId;

    public String getArticleId() {
        return articleId;
    }

    public void setArticleId(String articleId) {
        this.articleId = articleId;
    }
}
