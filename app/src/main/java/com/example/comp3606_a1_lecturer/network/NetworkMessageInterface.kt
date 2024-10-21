package com.example.comp3606_a1_lecturer.network

import com.example.comp3606_a1_lecturer.models.ContentModel

interface NetworkMessageInterface {
    fun onContent(content: ContentModel)
}